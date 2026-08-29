# Architectural rule: S_ItemDetails is a runtime ABI, not an authoring schema

Established while attempting CR-01C2 (see `research/evidence/CR-01C2/blocker.json`).

## The rule

```
game S_ItemDetails is an internal runtime ABI,
NOT a public Mod Kit authoring schema.
```

A mod must describe an item through a **stable, framework-owned semantic
definition**. A **build-specific Runtime adapter** then materialises that
definition into the real `S_ItemDetails` of whatever build is running.

## Why this is forced, not chosen

Three findings make direct authoring against `S_ItemDetails` unworkable:

1. **It is a game asset, not a public type.** `S_ItemDetails` is a
   `UserDefinedStruct` under `/Game/SurvivalGameKitV2/`, 2264 bytes, nesting at
   least ten further game-asset structs. D-10 forbids carrying those into the
   Mod Kit.
2. **Its field names are build-local.** `UserDefinedStruct` properties carry
   per-asset GUID suffixes (`Weight_7_794436A2…`). Any recreation gets different
   names, so tagged serialisation will not match.
3. **Its memory layout is the contract.** `AddRow` copies with
   `CopyScriptStruct` using the *destination* table's `RowStruct`, so a source
   buffer is always interpreted with the current build's layout. A mod shipping
   its own layout would be reinterpreted — a corruption class failure, not a
   clean error.

Any one of these would argue for an adapter; together they settle it.

## The resulting shape

```
Stable Mod ItemDefinition          <- authored by mods, versioned, build-independent
        |                             semantic IDs, no engine types, no GUID names
        v
build-specific S_ItemDetails adapter  <- owned by MiseryRuntime, one per game build
        |                             resolves fields by REFLECTION on the live struct,
        |                             fails closed on any missing/mismatched property
        v
Runtime ItemList registration      <- engine UDataTable::AddRow / RemoveRow (CR-01C1)
```

Consequences worth stating now:

- The adapter is the **only** component that knows `S_ItemDetails`. When the game
  updates, the adapter is re-derived; mod definitions do not change.
- The adapter must **fail closed**: a missing property, an unexpected
  `FProperty` class, offset or size, or an incompatible nested struct means no
  write at all, not a partial write.
- Field assignment must respect real property semantics. Direct stores are
  admissible only for proven trivially-assignable value types; `FString`,
  `FText`, `TArray`, nested structs and object/soft references require proper UE
  construction and copy semantics, never `memcpy` or raw pointer stores.
- Registration itself stays on the proven primitive: engine `AddRow`/`RemoveRow`,
  never raw `RowMap` mutation and never pointer aliasing between DataTables.
- Content the definition references is owned by the Runtime for the lifetime of
  the registration (CR-01A).

This document records the boundary only. The public Mod API is not designed here.
