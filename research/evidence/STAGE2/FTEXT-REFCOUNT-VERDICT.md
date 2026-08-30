# FText refcount: measured, not inferred

**Verdict: the counters MONOTONICALLY INCREASE. Recorded as a hard finding.**
**Not materially relevant to repeated Register/Unregister/hot reload. The
ItemDefinition work is not blocked on it.**

## What was inferred before

"3 leaked refcount increments per materialization" — arithmetic from the fact
that overwriting an `FText` field discards the reference `InitializeStruct` put
there, multiplied by three text fields. The counter value itself had **never
been read**. Only the *stability of the three default pointers* had been
measured.

## The read recipe, and why it can be trusted

Derived from the installed UE 5.4.4 source. The premise it replaced was wrong:
**`TTextData` does not exist in UE 5.4** — `FTextHistory` *is* the `ITextData`
(`TextHistory.h:139`), and it is the only implementation in the engine. A recipe
carried over from an older UE would have read the wrong offset.

```
FText + 0x00  ->  TRefCountPtr<ITextData>, the raw ITextData*      Text.h:811
ITextData is the polymorphic PRIMARY base -> vfptr at 0x00, size 8
TRefCountingMixin<FTextHistory> is non-polymorphic -> lands at 0x08
  its sole member: mutable std::atomic<uint32> RefCount    RefCounting.h:178,276

=> refcount = *(uint32*)(ITextData* + 0x08)
```

The `0x08` is an ABI conclusion, not a line of source — the engine carries no
`static_assert` on it. So every read is gated, and the decisive gate passed:
the `FString` at `+0x28/+0x30/+0x34` **round-trips exactly** to `"Name"`,
`"Short Name"` and `"Descriptions"` with lengths 5, 11 and 13 — the real default
values of the three `S_ItemDetails` text fields. That proves the object base and
the layout from a field `0x28` bytes away; the counter at `+0x08` follows from
the same derivation. All three share one vptr in the module image.

**A gate of mine was wrong and the measurement corrected it.** The first version
demanded `revisions == 0` unconditionally, reasoning from `Conv_StringToText`
producing a default `FTextId`. These defaults are *localized* — non-null
`LocalizedString`, revisions legitimately at 4 — so the gate fired on three
objects whose strings round-tripped perfectly. The gate was wrong, not the read.
It is now conditional on which kind of text the object is.

## The observed delta

**Coarse pass**, one sample per phase, 4 full register/unregister cycles, no
process restart:

| | after arm | after cleanup |
|---|---|---|
| cycle 0 | 1304, 1304, 1304 | 1304, 1304, 1304 |
| cycle 1 | 1305, 1305, 1305 | 1307, 1307, 1307 |
| cycle 2 | 1308, 1308, 1308 | 1308, 1308, 1308 |
| cycle 3 | 1309, 1309, 1309 | 1309, 1309, 1309 |

They climb. But the attribution is confounded, and visibly so: one rise happened
during a **cleanup**, which materializes nothing. The counter belongs to a shared
object, so every copy anywhere in the running game moves it.

**Fine pass**, three 4-byte reads every 150 ms across one full arm and one full
cleanup:

```
  [   0.000s] [1308, 1308, 1308]
  [  26.625s] [1309, 1309, 1309]  delta=[1, 1, 1]  <-- all three together
```

**One** state change in 150 seconds. All three moved **+1 at the same instant** —
the signature of our materialization, which writes the three fields in one tight
loop. Background traffic does not do that; it touches one text at a time for its
own reasons. And **no decrease, ever**.

So:

- the leak is **exactly +1 per default object per materialization**, observed,
  not calculated;
- **unregister returns nothing** — the reference was dropped before `AddRow` ever
  ran, so removing the row cannot recover it;
- the earlier `+5 over 4 cycles` was `+4` from us plus one from the game.

## Why this does not block the subsystem

The counter is `uint32`. At +1 per registration per field, reaching overflow
needs on the order of 4.29e9 registrations of a single item in one process.
Nothing about repeated Register/Unregister or hot reload approaches that, and the
three objects are process-lifetime defaults that are never freed regardless — so
no memory that would otherwise be reclaimed is lost. The imbalance is real,
permanent for the process, and harmless at any reachable scale.

## The identified fix, deliberately NOT taken yet

Raw `ITextData::Release` stays last resort: these are shared persistent engine
defaults, and an incorrect release is far more dangerous than a bounded
imbalance.

The narrowest correct replacement is **per-field property destruction**: locate
the `FTextProperty` for each field — which is already resolved by reflection —
and invoke its virtual `DestroyValue` on that field before writing ours in. That
lets the engine apply the correct semantics for the type instead of us
reimplementing refcount rules. It requires deriving one virtual slot on
`FProperty`, and it is recorded here as the direction rather than attempted.

Approaches ruled out while looking for something narrower:

- **Skip `InitializeStruct`** — the nested `FString`/`TArray` members would be
  garbage when `AddRow`'s `CopyScriptStruct` read them. Corruption, not a leak.
- **`InitializeStruct` then immediate `DestroyStruct`, then write** — balances the
  texts but leaves every other field destroyed, with the same corruption problem.
- **Swap the default into a second temp** — the two temps' defaults are the *same
  shared object*, so the swap is a no-op in refcount terms.

## Evidence

`hotreload-measured.json` (coarse, 4 cycles), `ftext-watch.json` (fine, 150 ms),
`research/instruments/ipp/ftext_refcount.py` (the gated reader),
`research/instruments/ipp/ftext_watch.py` (the sampler).
