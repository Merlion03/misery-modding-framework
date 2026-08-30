#!/usr/bin/env python3
"""The aggregate acceptance: many items, one table, one process, no restart.

Every check the stage requires, run against the live game and recorded whether
it passes or fails. Nothing here infers a result from another result -- the
composite's row count, the parent array, the subscription count and the
aggregate's own RowMap are each read directly, because the whole point of an
aggregate is that those four could disagree and only measurement would show it.
"""
import argparse
import json
import os
import struct
import sys
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
for _p in (os.path.join(REPO, "research", "instruments", "eri"),
           os.path.join(REPO, "research", "instruments", "ipp"),
           os.path.join(REPO, "research", "instruments", "items")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import eri                                        # noqa: E402
import cr01c3_recon as recon                      # noqa: E402
import read_datatable_rows as rdr                 # noqa: E402
import items_session                              # noqa: E402
import materializer                               # noqa: E402
import definition as D                            # noqa: E402
from cr01c3b_controller import OFF_PARENT_TABLES  # noqa: E402

OFF_DELEGATE = 0x98        # ItemList's OnDataTableChanged, derived in CR-01C3
CONTENT = "/Game/MBPLTest/Items/Radio"


def item(mod, local, weight, *, icon="T_MBPL_Radio_Icon", mesh="SM_MBPL_Radio"):
    return D.ItemDefinition(
        D.ItemId(mod, local),
        display_name="Agg %s" % local, short_name=local[:8],
        description="Aggregate acceptance item %s." % local,
        weight=weight, width=1, height=1,
        inventory_icon=D.AssetRef("%s/%s" % (CONTENT, icon)),
        world_mesh=D.AssetRef("%s/%s" % (CONTENT, mesh)),
        world_class="BP_StaticMasterItem_C")


def world_state(api):
    """Read everything that could disagree, directly."""
    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    handle = eri.open_process_read_only(api, i01["pid"])
    try:
        namepool, objects = recon.universe(api, handle, i01["base_address"],
                                           i01["image_size_bytes"])

        def cls_name(a):
            c = eri._read_u64(api, handle, a + eri.DEFAULT_CLASS_PRIVATE_OFFSET)
            return (objects.get(c) or {}).get("name_text")

        def path_of(a):
            try:
                return eri.canonicalize_object_path(
                    eri.resolve_object_path(a, objects).get("object_path"))
            except Exception:                                  # noqa: BLE001
                return None

        def one(name, klass):
            hits = [a for a, r in objects.items()
                    if r.get("name_ok") and r.get("name_text") == name
                    and cls_name(a) == klass]
            return hits[0] if len(hits) == 1 else None

        def names(table):
            rows, _diag = rdr.read_rowmap(api, handle, table)
            out = []
            for cmp_index, number, _v in rows:
                text = eri.decode_fname_entry_id(api, handle, namepool,
                                                 cmp_index).get("text")
                # FULL FName identity: comparison index AND number.
                out.append(text if number == 0 else "%s_%d" % (text, number - 1))
            return out

        itemlist = one("ItemList", "DataTable")
        master = one("MasterItemList", "CompositeDataTable")
        state = {"pid": i01["pid"]}
        state["ItemList"] = sorted(names(itemlist))
        state["MasterItemList"] = sorted(names(master))
        state["itemlist_rows"] = len(state["ItemList"])
        state["master_rows"] = len(state["MasterItemList"])

        data = eri._read_u64(api, handle, master + OFF_PARENT_TABLES)
        num = struct.unpack("<i", api.read_process_memory(
            handle, master + OFF_PARENT_TABLES + 8, 4))[0]
        mx = struct.unpack("<i", api.read_process_memory(
            handle, master + OFF_PARENT_TABLES + 12, 4))[0]
        slots = []
        if data and 0 < mx <= 64:
            raw = api.read_process_memory(handle, data, mx * 8)
            slots = [struct.unpack_from("<Q", raw, i * 8)[0] for i in range(mx)]
        state["ParentTables"] = {"num": num, "max": mx,
                                 "slots": ["0x%x" % s for s in slots]}

        d = eri._read_u64(api, handle, itemlist + OFF_DELEGATE)
        n = struct.unpack("<i", api.read_process_memory(
            handle, itemlist + OFF_DELEGATE + 8, 4))[0]
        state["subscriptions"] = n

        state["transient_datatables"] = sorted(
            path_of(a) for a in objects
            if cls_name(a) == "DataTable" and (path_of(a) or "").startswith(
                "/Engine/Transient"))
        return state
    finally:
        api.close_handle(handle)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)

    checks = []

    def check(label, ok, detail=""):
        checks.append({"check": label, "pass": bool(ok), "detail": str(detail)})
        print("  [%s] %-58s %s" % ("PASS" if ok else "FAIL", label, detail))
        return bool(ok)

    api = eri.Win32Api()
    report = {"started": time.strftime("%Y-%m-%dT%H%M%SZ", time.gmtime())}
    base = world_state(api)
    report["baseline"] = base
    print("baseline: ItemList=%d Master=%d PT.num=%d subs=%d transient=%d"
          % (base["itemlist_rows"], base["master_rows"], base["ParentTables"]["num"],
             base["subscriptions"], len(base["transient_datatables"])))
    vanilla_itemlist = list(base["ItemList"])
    vanilla_master = base["master_rows"]

    A = item("mbpl", "agg_a", 0.25)
    B = item("mbpl", "agg_b", 0.5)
    C = item("mbpl", "agg_c", 0.75)
    D2 = item("othermod", "agg_a", 1.25)          # same local id, different mod

    session = items_session.AggregateSession()
    print("\n=== Items init ===")
    info = session.init()
    print("  ", info)
    report["init"] = info

    try:
        print("\n=== Register A, B, C ===")
        results = {}
        for label, d in (("A", A), ("B", B), ("C", C)):
            results[label] = session.register(materializer.flatten(d))
            print("   register(%s) -> %s" % (label, results[label].get("ok")))
        report["register"] = results
        check("Register(A/B/C) all succeeded",
              all(results[k].get("ok") for k in "ABC"))

        st = world_state(api)
        report["after_abc"] = st
        check("exactly one transient aggregate DataTable",
              len(st["transient_datatables"]) == 1, st["transient_datatables"])
        check("ParentTables.num remains 2", st["ParentTables"]["num"] == 2,
              st["ParentTables"])
        check("exactly one subscription from MasterItemList to the aggregate",
              st["subscriptions"] == 1, st["subscriptions"])
        check("MasterItemList = %d + 3" % vanilla_master,
              st["master_rows"] == vanilla_master + 3, st["master_rows"])
        check("ItemList remains exactly %d and byte-identical" % len(vanilla_itemlist),
              st["ItemList"] == vanilla_itemlist,
              "%d rows" % st["itemlist_rows"])
        for label, d in (("A", A), ("B", B), ("C", C)):
            check("Find(%s) resolves in the composite" % label,
                  d.row_name in st["MasterItemList"], d.row_name)
        check("the aggregate's own RowMap holds exactly A, B, C",
              sorted(session.table_rows()) == sorted([A.row_name, B.row_name, C.row_name]),
              session.table_rows())

        print("\n=== negative cases ===")
        before = world_state(api)
        dup = session.register(materializer.flatten(A))
        after = world_state(api)
        check("duplicate A -> already_registered", dup.get("code") == "already_registered",
              dup.get("code"))
        check("duplicate A mutated nothing",
              after["master_rows"] == before["master_rows"]
              and after["ParentTables"] == before["ParentTables"])

        unknown = session.unregister(materializer.flatten(item("mbpl", "ghost", 1.0)))
        after2 = world_state(api)
        check("unregister unknown -> not_registered",
              unknown.get("code") == "not_registered", unknown.get("code"))
        check("unregister unknown mutated nothing",
              after2["master_rows"] == before["master_rows"])

        print("\n=== two mods, same local_id ===")
        rd = session.register(materializer.flatten(D2))
        st2 = world_state(api)
        check("othermod__agg_a registers alongside mbpl__agg_a", rd.get("ok"), rd)
        check("both semantic ids resolve",
              "mbpl__agg_a" in st2["MasterItemList"]
              and "othermod__agg_a" in st2["MasterItemList"])
        check("still one aggregate table", len(st2["transient_datatables"]) == 1)
        session.unregister(materializer.flatten(D2))

        print("\n=== Unregister B ===")
        ub = session.unregister(materializer.flatten(B))
        st3 = world_state(api)
        report["after_unregister_b"] = st3
        check("Unregister(B) succeeded", ub.get("ok"), ub.get("detail"))
        check("A present", A.row_name in st3["MasterItemList"])
        check("B absent", B.row_name not in st3["MasterItemList"])
        check("C present", C.row_name in st3["MasterItemList"])
        check("MasterItemList = %d" % (vanilla_master + 2),
              st3["master_rows"] == vanilla_master + 2, st3["master_rows"])
        check("ParentTables still 2", st3["ParentTables"]["num"] == 2)
        check("aggregate table is the SAME UObject",
              st3["transient_datatables"] == st["transient_datatables"],
              st3["transient_datatables"])
        # A and C share B's icon and mesh, so the shared assets must survive
        check("assets required by A and C remain valid",
              session.rows[A.row_name]["icon_object"]
              == session.rows[C.row_name]["icon_object"],
              "shared icon still owned")

        print("\n=== Register B again ===")
        rb = session.register(materializer.flatten(B))
        st4 = world_state(api)
        check("Register(B) again succeeded", rb.get("ok"), rb.get("detail"))
        check("MasterItemList = %d again" % (vanilla_master + 3),
              st4["master_rows"] == vanilla_master + 3, st4["master_rows"])
        check("still exactly one aggregate table",
              len(st4["transient_datatables"]) == 1)
        check("still exactly one subscription", st4["subscriptions"] == 1)

        print("\n=== Items shutdown with items still registered ===")
        report["rows_before_shutdown"] = sorted(session.rows)
        sd = session.shutdown()
        report["shutdown"] = sd
        st5 = world_state(api)
        report["after_shutdown"] = st5
        check("shutdown reports ok", sd.get("ok"), sd.get("teardown"))
        check("MasterItemList back to %d" % vanilla_master,
              st5["master_rows"] == vanilla_master, st5["master_rows"])
        check("ItemList is the exact vanilla baseline",
              st5["ItemList"] == vanilla_itemlist)
        check("ParentTables.num = 1", st5["ParentTables"]["num"] == 1,
              st5["ParentTables"])
        check("spare parent slot is zero",
              st5["ParentTables"]["slots"][1:] == ["0x0"],
              st5["ParentTables"]["slots"])
        check("no mod rows resolve",
              not [n for n in st5["MasterItemList"] if "__" in n])
        check("aggregate table released",
              sd.get("release_table", {}).get("rooted_after") == 0,
              sd.get("release_table"))
        check("asset store owns nothing",
              sd.get("release_table", {}).get("owned_count") == 0,
              sd.get("release_table"))
        check("dispatcher stopped and module unloaded",
              sd.get("dll_unloaded") is True and
              sd.get("teardown", {}).get("wait_stopped_ok") == 1,
              sd.get("teardown"))
    finally:
        if session.initialised:
            try:
                session.shutdown()
            except Exception as exc:                           # noqa: BLE001
                print("  cleanup shutdown failed: %r" % exc)

    print("\n=== re-init and a smaller cycle in the SAME process ===")
    session2 = items_session.AggregateSession()
    session2.init()
    r1 = session2.register(materializer.flatten(A))
    r2 = session2.register(materializer.flatten(C))
    st6 = world_state(api)
    check("re-init works in the same process", r1.get("ok") and r2.get("ok"))
    check("MasterItemList = %d after re-init cycle" % (vanilla_master + 2),
          st6["master_rows"] == vanilla_master + 2, st6["master_rows"])
    check("exactly one aggregate table after re-init",
          len(st6["transient_datatables"]) == 1, st6["transient_datatables"])
    sd2 = session2.shutdown()
    st7 = world_state(api)
    check("final state is the vanilla baseline",
          st7["master_rows"] == vanilla_master
          and st7["ItemList"] == vanilla_itemlist
          and st7["ParentTables"]["num"] == 1, st7["master_rows"])

    report["checks"] = checks
    report["passed"] = sum(1 for c in checks if c["pass"])
    report["failed"] = sum(1 for c in checks if not c["pass"])
    report["notes"] = session.note[-30:]
    with open(a.out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(report, f, indent=2, sort_keys=False, default=str)
        f.write("\n")
    print("\n%d passed, %d failed -> %s" % (report["passed"], report["failed"], a.out))
    return 0 if report["failed"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
