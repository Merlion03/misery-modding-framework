# E-3c — closure

A Blueprint cooked in our Mod Kit against a generated surrogate, shipped without
that surrogate, binds at runtime to MISERY's own gameplay Blueprint class.

    mod author in the Mod Kit
      -> derives from BP_StaticMasterItem_C
      -> cooks with UE 5.4.4
      -> the surrogate parent is NOT distributed
      -> the production framework mounts the container
      -> the real game resolves the child against its OWN parent
      -> constructed, and a genuine subclass

## The measured facts

| Fact | Value | Evidence |
|---|---|---|
| Surrogate completeness the cooker demanded | **S0** — object path and class name only | `s0-cook.json` |
| Cooked child's super | import, full path `…BP_StaticMasterItem.BP_StaticMasterItem_C` | `s0-cooked-child-references.json` |
| Container contents | one package, the child; surrogate absent | `package-and-install.json` |
| Child `SuperStruct` | `0x192c43c7080` | `runtime-proof.json` |
| Resolver's parent `UClass*`, found independently | `0x192c43c7080` | same |
| Inherited `ItemAmount` | owner = the real parent, offset 688, not declared by the child | same |
| `PropertiesSize` | parent 856, child 856 | same |
| Installation after uninstall | MATCH against the vanilla baseline | full re-hash, 52 files |

Pointer identity is the load-bearing fact. The surrogate and the real parent
share an object path by design, so a name or path match would have proved
nothing; the only question was which `UClass` object the child points at, and
the answer came from the production resolver's own content-anchor pass.

## What the gate establishes

The **mechanism** is proven for `BP_StaticMasterItem_C` on
`build_key=sha256:bace50f7…f013331`:

* a generated surrogate at the real object path is enough for the cooker at S0;
* the cooked child references the parent by full object path, as an import;
* the surrogate need not ship, and does not;
* the game resolves that import to its own class;
* the resulting class is a genuine subclass — real ancestry, real inherited
  members at their real offsets, constructible.

## What it does not establish

* **Other parents.** One parent was measured. The weapon, holdable, inventory
  and build-part trees are untested, and LOG-0063 shows they differ in size and
  shape.
* **A public API.** plan.md §10.3 requires ≥0.95 and runtime confirmation before
  a public API rests on a result; this is one experiment on one class.
* **Usefulness.** The child is empty. It is a genuine subclass that does
  nothing, which is exactly what the gate asked for and no more.
* **E-3b.** Still valuable as a cheap native-parent control, isolating "does the
  cook+load pipeline work" from "is the needed parent reachable" (LOG-0065
  finding 7).

## Two things the run taught that outlive it

**Mounted and registered is not loaded.** `FPakFile::bIsMounted` true and a
non-null `FIoContainerHeader` say the container is there and its packages are
known. They say nothing about whether any object has been created. UE loads on
demand, and an isolated mod class that nothing references is never asked for.
Recorded as `preregistration-addendum-1.md`.

**An unrooted object does not survive to be read.** The probe constructs into
the transient package and roots nothing; reading its addresses back seconds
later out of process found collected memory. Readings that must describe such an
object have to be taken on the game thread, while it is alive.
