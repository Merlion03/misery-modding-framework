# E-3c pre-registration, addendum 1 — activation, not a change of criteria

Written **before** the live call it authorises. It records a distinction the
original pre-registration did not anticipate and states exactly what the probe
may do about it. The PASS criteria in `preregistration.md` are unchanged.

## The observed distinction

    mounted + package registered
      does not imply
    UObject/package loaded

Measured, not reasoned: with `Mod_e3cprobe_P.pak` reporting
`FPakFile::bIsMounted == true` and `FIoContainerHeader` non-null — the same two
separately-read facts Stage 3 established, with `CT03Probe20260828_P` still
reading `packages_registered: false` as the control — a full object-universe walk
found **no** object named `BP_MiseryTestWorldItem_C` anywhere in the process.

UE loads a package when something asks for it. Nothing had. The isolated E-3c
child has no natural reference from MISERY: no level places it, no table names
it, no loaded package imports it. So it was never loaded, and that is neither a
mount failure nor an unresolved import.

The original pre-registration enumerated two sub-cases for "child class not
found" — parent absent, or parent present and the import unresolved — and this is
a third. Recording it here rather than folding it into either: reading this as
one of the two already written down would have produced a confident false
negative.

## What the probe is authorised to do

Request that exact child, by its cooked object path, through the game's ordinary
reflected loading path, on the game thread:

    UKismetSystemLibrary::LoadAsset_Blocking

with the soft path built from the cooked child's own package and asset names:

    /Game/Mods/e3cprobe/BP_MiseryTestWorldItem . BP_MiseryTestWorldItem_C

This satisfies the precondition "child class loads" and nothing more.

## What the probe must not do

It must not, at any point:

* supply or substitute the parent;
* patch imports;
* modify `SuperStruct`;
* register the class manually;
* inject the surrogate;
* repair package state;
* perform any operation that could make inheritance succeed artificially.

The probe is written so that these are not merely unintended but absent: it
contains no code that writes to any engine structure. Its only writes are into
its own IO page and into stack-local parameter blocks handed to the engine's own
reflected functions.

## The loader result is evidenced separately

Recorded as its own three-part fact, so that loading and inheriting cannot be
conflated:

    before LoadAsset_Blocking:  the child class is absent from the process
    the probe requests:         the exact cooked child object path
    after:                      the child class is present

**Successful loading is not inheritance success.** It establishes the
precondition and nothing else. Every E-3c criterion is evaluated afterwards, on
the loaded class, exactly as `preregistration.md` states them:

    child UClass exists
      -> Child.SuperStruct == the independently resolved real
         BP_StaticMasterItem_C UClass*
      -> an inherited member absent from the S0 surrogate resolves through
         the child
      -> the child can be constructed/spawned
      -> runtime ancestry reaches the real MISERY parent
      -> the surrogate package/class is absent from distributed content AND
         absent from the runtime process

## The inherited-capability exercise

`ItemAmount` — `FIntProperty`, offset 688 on the real parent
(`research/evidence/CR-01/master-classes-i05-i06.json`). Chosen as the smallest
safe deterministic member already established by prior reflection evidence: a
plain integer, read-only, no world interaction, no gameplay side effect.

The S0 surrogate has **no properties at all**, so any inherited member
discriminates; this one is simply the least ambiguous to read. It is read
through the child, and its owning struct is required to be the real parent
rather than the child.

No other member of `BP_StaticMasterItem` is examined. The purpose is the
inheritance mechanism, not a map of the parent class.
