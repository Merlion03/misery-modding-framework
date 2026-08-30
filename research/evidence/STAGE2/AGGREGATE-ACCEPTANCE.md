# Aggregate runtime table — acceptance

**42 checks, 42 passed, 0 failed.** One process, no restart, live game.
Evidence: `aggregate-acceptance.json`.

## What replaced what

Before, each registration created its **own** `UDataTable` and attached it into
the composite's single spare parent slot. That supports exactly one item and
then fails closed at `ParentTables.Num == 2` — correctly, since no array growth
is authorised. It was never the intended architecture.

Now: **one runtime-owned aggregate table, `RowStruct` = the real
`S_ItemDetails`, attached to `MasterItemList` once, one row per registered
`ItemId`.**

## The mechanism change is one job

`AddRow` and `RemoveRow` both key on `(io->table_ptr, io->row_fname)`. So a
fixed table plus a re-interned row name is the whole of what a second, third or
tenth item needs. `JobInternRow` does exactly that, refuses if the name would
collide with the neutral trigger — that trigger is *removed* from `ItemList` to
force the composite rebuild, so a collision there would delete real data — and
reuses the spare `pad4` field, leaving the wire format unchanged at 5648 bytes.

## The architectural consequence

The aggregate is rooted by the probe's asset store, and that store dies with the
probe module. An aggregate that outlives individual registrations therefore
**requires the module to stay loaded across them** — so the subsystem is a live
session, not a sequence of independent child processes.

## Attachment policy — stated, and tested

The aggregate attaches at init and **stays attached until shutdown, even when
empty**. Detach-on-last-row was rejected: attach and detach each rebuild ~496
composite rows and invalidate every `MasterItemList` row pointer, so a mod that
registers and unregisters one item repeatedly would churn the whole table for
nothing. An empty attached parent contributes no rows.

## Measured

| | |
|---|---|
| Register A, B, C | one transient DataTable, `ParentTables.num` 2, **one** subscription, Master 496+3, ItemList exactly 496 and byte-identical |
| aggregate's own RowMap | exactly A, B, C |
| duplicate A | `already_registered`, zero mutation |
| unregister unknown | `not_registered`, zero mutation |
| `othermod__agg_a` beside `mbpl__agg_a` | both register — same local id, different mod, different semantic id |
| Unregister B | A present, B absent, C present, Master 498, `num` still 2, **same table UObject**, shared icon still owned by A and C |
| Register B again | Master 499, still one table, still one subscription |
| shutdown with items registered | Master back to 496, ItemList exact vanilla baseline, `num` 1, spare slot `0x0`, no mod rows, table released (`rooted_after` 0), store owns nothing, dispatcher stopped, module unloaded |
| re-init in the same process | works; smaller cycle to 498 and back to the vanilla baseline |

## The identity rule, kept

Row names are compared by **full FName identity — comparison index AND number**,
never by comparison index alone. An earlier version of the collision oracle
keyed on the index and reported 460 rows against a real 496, collapsing
`BuildPart_Bookcase_1` and friends. A collision oracle that undercounts is one
that can miss a collision.

The `__` namespace convention is true of this 496-row build and useful by
construction, but it is **not** the guarantee. The canonical row list read from
the live composite remains the authoritative oracle.

## Two defects found and fixed on the way

- **The controller's inventory check compared the weight delta against the
  literal `0.5`** — the radio's weight. Any other item would have failed a check
  that had nothing to do with it.
- **`_bind_item_bytes` re-read and re-hashed the ~100 MB game executable on
  every register and unregister**, turning this run into an hour. The signature
  bytes and carrier addresses cannot change while a session is live, so they are
  captured once at init.

## A process error worth recording

A later public-API run was killed by a ten-minute tool timeout **mid-session**,
leaving one row in the aggregate, the table still attached and the module still
loaded. The Python session object died with the process, so `shutdown()` could
not be called. Recovery was a game restart, which is complete here because the
vanilla `ItemList` is never written and the session grants nothing to the
inventory — but the lesson is that a session holding live game state must be
driven from a process that cannot be killed by a foreground timeout.
