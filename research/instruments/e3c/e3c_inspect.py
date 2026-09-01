#!/usr/bin/env python3
"""E-3c: what identity does the cooked child actually reference?

Read BEFORE any live test, because it decides whether a live test is even
meaningful. The pre-registration requires the child's cooked import to name the
real parent by its exact object path; if it names something else, no runtime
result could be interpreted.

This reads the package the cooker wrote. It does not ask the editor what it
believes, and it does not ask the builder what it intended -- both of those have
already said yes, and neither is the artifact that ships.
"""
import argparse
import json
import os
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
for _p in (os.path.join(REPO, "tools"), os.path.join(REPO, "tools", "modkit")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from content import package_summary as ps                         # noqa: E402

PARENT_PACKAGE = ("/Game/SurvivalGameKitV2/Blueprints/Items/WorldItems/"
                  "BP_StaticMasterItem")
PARENT_CLASS = "BP_StaticMasterItem_C"


def read_package(path):
    with open(path, "rb") as handle:
        data = handle.read()
    summary = ps.read_summary(data, path)
    names = ps.read_name_map(data, summary)
    imports = ps.read_import_map(data, summary, names)
    exports = ps.read_export_map(data, summary, names)
    return {"summary": summary, "names": names, "imports": imports,
            "exports": exports}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--child", required=True, help="the cooked child .uasset")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)

    checks = []

    def check(label, ok, detail=""):
        checks.append({"check": label, "pass": bool(ok), "detail": str(detail)})
        print("  [%s] %s%s" % ("PASS" if ok else "FAIL", label,
                               "" if ok else "  -- %s" % detail))
        return bool(ok)

    package = read_package(a.child)
    report = {"child": a.child,
              "names": package["names"],
              "imports": package["imports"],
              "exports": [{k: e.get(k) for k in
                           ("object_name", "class_name", "super_index",
                            "class_index", "outer_index")}
                          for e in package["exports"]]}

    print("=== the cooked child package ===")
    print("  names   : %d" % len(package["names"]))
    print("  imports : %d" % len(package["imports"]))
    print("  exports : %d" % len(package["exports"]))

    # The parent's PACKAGE must be named, because that is what the loader
    # resolves against the already-registered package in the game.
    joined = " ".join(package["names"])
    check("the parent package path appears in the child's name map",
          PARENT_PACKAGE in joined, PARENT_PACKAGE)
    check("the parent class name appears in the child's name map",
          PARENT_CLASS in joined, PARENT_CLASS)

    # An import naming the parent class. This is the reference the runtime must
    # resolve to MISERY's own class.
    parent_imports = [i for i in package["imports"]
                      if PARENT_CLASS in str(i.get("object_name"))
                      or PARENT_PACKAGE in str(i.get("object_name"))]
    report["parent_imports"] = parent_imports
    for entry in parent_imports:
        print("   import: %s  class=%s  package=%s"
              % (entry.get("object_name"), entry.get("class_name"),
                 entry.get("class_package")))
    check("the child imports the parent by name", bool(parent_imports),
          "no import names %s" % PARENT_CLASS)

    # THE FIELD THAT DECIDES THE EXPERIMENT: the child class export's super.
    #
    # UE stores it as an FPackageIndex, whose sign is the whole meaning:
    #   0        null
    #   n > 0    export[n - 1]      -- something inside THIS package
    #   n < 0    import[-n - 1]     -- something in ANOTHER package
    #
    # A positive super would mean the child inherits from something we shipped,
    # which is the surrogate-binding failure. A negative one pointing at the
    # parent-class import is what the runtime then has to resolve against
    # MISERY's own class. The reader leaves it unresolved, so it is resolved
    # here rather than reported as None -- an unread field cannot be evidence.
    def resolve_index(value):
        if not value:
            return None, "null"
        if value > 0:
            index = value - 1
            entry = package["exports"][index] if index < len(package["exports"]) else None
            return entry, "export[%d]" % index
        index = -value - 1
        entry = package["imports"][index] if index < len(package["imports"]) else None
        return entry, "import[%d]" % index

    for export in package["exports"]:
        if str(export.get("object_name")) != "BP_MiseryTestWorldItem_C":
            continue
        entry, where = resolve_index(export.get("super_index"))
        name = str(entry.get("object_name")) if entry else "(unresolved)"
        report["child_super"] = {"raw": export.get("super_index"),
                                 "kind": where, "name": name,
                                 "entry": entry}
        print("   child class super: %s -> %s = %s"
              % (export.get("super_index"), where, name))
        check("the child's super is an IMPORT, not something in our package",
              str(where).startswith("import"),
              "%s -- a positive index would mean it inherits from what we ship"
              % where)
        check("the child's super names the real parent class",
              name == PARENT_CLASS, name)
        if entry:
            check("the super import is a BlueprintGeneratedClass",
                  str(entry.get("class_name")) == "BlueprintGeneratedClass",
                  entry.get("class_name"))

            # THE FULL OBJECT PATH, not just the leaf name.
            #
            # "an import called BP_StaticMasterItem_C" is not the same claim as
            # "an import at /Game/SurvivalGameKitV2/.../BP_StaticMasterItem.
            # BP_StaticMasterItem_C". A leaf name could match a class in some
            # other package entirely, and the runtime resolves the whole path.
            # So the outer chain is walked to its root and reassembled.
            chain, cursor, guard = [], entry, 0
            while cursor is not None and guard < 8:
                chain.append(str(cursor.get("object_name")))
                outer, _where = resolve_index(cursor.get("outer_index"))
                cursor = outer
                guard += 1
            report["super_outer_chain"] = chain
            full = ".".join(reversed(chain))
            report["super_full_path"] = full
            print("   resolved super path: %s" % full)
            check("the super resolves to the real parent's FULL object path",
                  full == PARENT_PACKAGE + "." + PARENT_CLASS,
                  "%s vs %s" % (full, PARENT_PACKAGE + "." + PARENT_CLASS))

    supers = [e for e in package["exports"] if e.get("super_index")]
    report["exports_with_super"] = [
        {"object_name": e.get("object_name"),
         "super_index": e.get("super_index"),
         "super_resolved": e.get("super_resolved")} for e in supers]
    for entry in supers:
        print("   export %s -> super %s (%s)"
              % (entry.get("object_name"), entry.get("super_index"),
                 entry.get("super_resolved")))

    # NOTHING of ours may name the surrogate as a package we ship. This file is
    # the child; the surrogate being referenced is REQUIRED, the surrogate being
    # PRESENT in the container is forbidden -- and that is the container's
    # question, checked separately.
    report["checks"] = checks
    report["passed"] = sum(1 for c in checks if c["pass"])
    report["failed"] = sum(1 for c in checks if not c["pass"])
    report["verdict"] = "PASS" if report["failed"] == 0 else "FAIL"

    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=2, default=str)
        handle.write("\n")
    print("\n%s -- %d passed, %d failed -> %s"
          % (report["verdict"], report["passed"], report["failed"], a.out))
    return 0 if report["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
