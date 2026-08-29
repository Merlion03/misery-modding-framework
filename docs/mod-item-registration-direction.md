# Production direction — mod item registration

Fixed by the owner after `CR-01C2R PASS` (`b016eee`).

```
Stable Mod ItemDefinition
  -> build-specific reflected S_ItemDetails materializer
  -> engine AddRow / RemoveRow
```

## What each layer is, and why the split exists

**Stable Mod ItemDefinition** — the public authoring schema a mod ships. It is
*ours*, versioned by us, and deliberately unrelated to the game's internal
struct. It must stay stable across MISERY patches.

**Build-specific reflected `S_ItemDetails` materializer** — the adapter. For one
exact build it resolves the real `RowStruct` and every field it writes by live
reflection (name, `FProperty` class, offset, size — all four must match or it
refuses), allocates a temp from the game allocator, constructs it with the
struct's own `InitializeStruct`, populates only fields whose assignment
semantics are proven, and destroys the temp again. Proven end to end in
`CR-01C2R` (`research/evidence/CR-01C2R/acceptance.json`).

This layer is expected to change on every game patch. That is its job: it
absorbs the churn so the layer above it does not.

**Engine `AddRow` / `RemoveRow`** — the only sanctioned registration primitive.
No raw `RowMap` mutation. No pointer aliasing between `DataTable`s. The engine
owns row memory end to end, which makes double-free and dangling rows
structurally impossible from our side.

## The rule this encodes

`game S_ItemDetails is an internal runtime ABI, NOT a public Mod Kit authoring
schema` — see [mod-item-definition-boundary.md](mod-item-definition-boundary.md).

A mod never sees `S_ItemDetails`. It sees the stable definition; the
materializer is the only thing that ever touches the game struct, and it does so
through reflection it verified this run, not through a layout it remembers.

## Registration target, corrected in CR-01C3

The inventory definition resolver (`BP_SGKFunctions_C::"SGK ItemDetails"`) reads
**`MasterItemList`**, a `UCompositeDataTable`, not the plain `ItemList`
`UDataTable` this primitive was proven against. 71 live UFunctions reference
`MasterItemList`; only 8 reference `ItemList`, and 7 of those reference both.

`UCompositeDataTable` overrides `AddRow` and `RemoveRow` to do nothing
(`CompositeDataTable.cpp:191-199`; in this binary both composite vtable slots
point at RVA `0xf309c0`, a bare `ret`). **So the composite is never a valid
target for the primitive.**

The parent still is, and that turns out to be enough. `UDataTable::AddRow` opens
a `FScopedDataTableChange`, whose destructor calls `HandleDataTableChanged()` ->
`OnDataTableChanged().Broadcast()`; `UCompositeDataTable` subscribes itself to
every parent's change delegate (`CompositeDataTable.cpp:338`) and the handler
rebuilds the cached row map from the parents. Verified live: `ItemList`'s
delegate invocation list holds exactly one entry, and it is a `TWeakObjectPtr`
whose index *and* serial number both match `MasterItemList`.

So the third layer stands as written, with one clarification:

```
                                    -> engine AddRow / RemoveRow on ItemList
                                       (the PARENT; the engine rebuilds
                                        MasterItemList by itself)
```

Cost: each mutation rebuilds all ~496 composite rows (~1.1 MB of churn) and
invalidates every `MasterItemList` row pointer. Blueprint consumers copy rows by
value and are unaffected. `FScopedDataTableChange` is refcounted per table, so
batching many registrations into one rebuild is possible in principle — its
constructor RVA is not yet derived.

Full evidence: `research/evidence/CR-01C3/composite-resolution.json`.
