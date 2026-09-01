# E-3c — Blueprint inheritance from a real MISERY gameplay class (pre-registration)

Written **before** any cook or live run. Tier A: the acceptance criteria and the
reading of every failure are fixed here so that neither can be chosen after
seeing the result.

## Question

Can a mod author, in our Mod Kit, derive a Blueprint from a real MISERY gameplay
**Blueprint** class, cook it with UE 5.4.4, ship it *without* the parent, and
have the real game resolve the child against its own parent class and construct
a genuine subclass?

    mod author in our Mod Kit
      -> derives a Blueprint from a real MISERY gameplay Blueprint class
      -> cooks with exact UE 5.4.4
      -> generated/surrogate parent is NOT distributed
      -> mod package is mounted by the production framework
      -> in the real game the child resolves against MISERY's real parent
      -> object can be constructed/spawned and behaves as a genuine subclass

## The principle this must not violate

    authoring-time surrogate/generated parent
      !=
    runtime replacement of the game's class

The surrogate exists so the editor has something to compile against. It is an
authoring-time fiction. It must never be shipped, never be mounted, and never be
what the game resolves. If the child ever binds to our surrogate at runtime, the
experiment has FAILED even if the object spawns and behaves — a subclass of our
own stub is not a subclass of the game's class, and would be a far worse outcome
than a clean refusal, because it would look like success.

## Why this parent

`/Game/SurvivalGameKitV2/Blueprints/Items/WorldItems/BP_StaticMasterItem.BP_StaticMasterItem_C`

One parent, chosen narrowly, on four grounds:

1. **It is an Actor** (`Actor -> Object`, LOG-0063), so "construct/spawn" is a
   question with a real answer rather than a component-instantiation proxy.
2. **It is certainly loaded in gameplay** — 14 live instances measured
   (LOG-0063). A negative result therefore cannot be explained away by "the
   parent was not loaded yet".
3. **The production resolver already resolves it independently.** Stage 5B's
   `Request::world_item_class` is `BP_StaticMasterItem_C`, so the framework can
   hand back the `UClass*` the GAME loaded, from a code path that knows nothing
   about this experiment. That gives an identity oracle that is not our own
   cooked package talking about itself.
4. **It is the smallest meaningful gameplay parent available.** 15 properties and
   42 functions (`research/evidence/CR-01/master-classes-i05-i06.json`), against
   the weapon/consumable trees which are larger and sit further down the same
   hierarchy. LOG-0063 established there is **no native parent** in
   `/Script/MISERY` suitable for a content mod, so a Blueprint parent is not a
   preference here, it is the only route.

Deliberately NOT chosen for the first proof: `BP_MasterWeapon_C`,
`BP_MasterHoldable_C`, `BP_MasterInventory_C`. Broadening to a catalog before one
parent works would multiply the unknowns rather than resolve any.

## Method

1. **Surrogate generation.** From existing CR-01 reflection evidence, generate an
   editor-side `BP_StaticMasterItem` at the parent's exact object path, carrying
   as much of the real class's shape as the cooker actually demands.
2. **Child.** `BP_MiseryTestWorldItem : BP_StaticMasterItem_C`, authored through
   the Mod Kit like any other mod asset.
3. **Cook** with the exact UE 5.4.4 already used by Stage 3.
4. **Exclude the surrogate** from the container, and verify its absence by
   reading the container back rather than by trusting the build.
5. **Mount** through the production framework — the Stage 5B path, unmodified.
6. **Resolve and construct** in the live game.

### Surrogate completeness is MEASURED, not assigned

LOG-0065 finding 5, kept deliberately: the temptation to decide in advance that
"everything is needed" or "the name is enough" is equally unfounded either way.
The surrogate is grown in stages and each stage records what the compiler or
cooker actually demanded:

| Stage | Surrogate carries |
|---|---|
| S0 | object path and class name only |
| S1 | + the 15 reflected properties, with types |
| S2 | + the 42 reflected function signatures |
| S3 | + whatever S0-S2 proved the toolchain additionally demands |

The first stage that cooks is the answer to "how complete must a surrogate be",
and that answer is a result of this experiment, not an input to it.

## Pre-registered outcomes (fixed before the run)

**PASS** requires ALL of:

1. The container contains the child package and **no** package at the parent's
   path — read back from the container, not asserted by the builder.
2. The child's cooked import references the parent by the exact object path
   above (read from the package's import table).
3. In the live game the child `UClass` is found by name.
4. `child->SuperStruct` is **pointer-identical** to the `UClass*` the production
   resolver independently resolved for `BP_StaticMasterItem_C` in the same
   process. Pointer identity, not name equality: two classes may share a name.
5. The class chain from the child terminates at `/Script/CoreUObject.Object`,
   passing through the real parent (`readiness.class_super_chain`, which
   re-verifies the `SuperStruct` offset on every walk).
6. An instance is constructed/spawned successfully.
7. The instance exposes an inherited member that came from the REAL parent and
   is not present in the surrogate — the concrete discriminator between "a
   subclass of the game's class" and "a subclass of our stub".
8. Unmounting leaves the installation at its exact vanilla baseline.

**Each distinct failure, and what it means:**

- **The cooker refuses the child at every surrogate stage** ⇒ `blocked: the
  toolchain will not compile against a generated parent`. This is a statement
  about the cooker, NOT about whether MISERY could resolve such a child. Record
  what each stage demanded; that record is the useful product.
- **Cook succeeds; the container contains a package at the parent's path** ⇒
  FAIL, and the run stops before mounting. Shipping a surrogate is the one
  outcome that must never reach the game, because it would produce a false PASS.
- **Child package mounts; the child class is not found** ⇒ the import did not
  resolve. Distinguish two sub-cases before interpreting: parent absent from the
  process (should be impossible — 14 live instances), versus parent present and
  the import still unresolved. Only the second bears on E-3c.
- **Child found, but `SuperStruct` is not the game's class object** ⇒ FAIL,
  regardless of whether it spawns. This is the surrogate-binding case above.
- **Child found and correctly parented, but construction fails** ⇒ partial:
  inheritance resolved, instantiation did not. Report as its own verdict; do not
  round it up to PASS or down to a refutation of the route.
- **Constructs, but an inherited member is missing or misplaced** ⇒ layout did
  not relink as CK-04 predicts. This would contradict CK-04's finding on this
  build and must be reported as such rather than smoothed over.
- **The game crashes** ⇒ FAIL, reported with the state at the time. No retry
  loop against a live game.

## What a PASS does and does not license

A PASS establishes that ONE gameplay parent works by this route, on this build.
It does not establish that the route generalises to the weapon or inventory
trees, does not license a public API (plan.md §10.3 requires >=0.95 and runtime
confirmation for that), and says nothing about whether the resulting mod is
*useful* — only that it is a genuine subclass.

It also does not retire E-3b. LOG-0065 finding 7: E-3b keeps its value as a cheap
native-parent control, isolating "does the cook+load pipeline work" from "is the
needed parent reachable".

## What is reused, not rebuilt

Stage 3's cooking and container infrastructure (`tools/modkit/`), Stage 5B's
production mount path, CR-01's reflection evidence, and
`readiness.class_super_chain` for ancestry. Nothing unrelated is redesigned.

## Build fingerprint

`build_key = sha256:bace50f7185d095d03ee18a2fea701c747810c31f2037bda21ea57a81f013331`
(`misery-24953925-ue5.4.4-bace50f7185d`). Any other build invalidates this
pre-registration rather than being tested against it.

## Prior state this replaces

`research/unknowns.md` records E-3c and CK-09 as UNKNOWN with an expectation of
`blocked`, corrected by D-11 and then re-grounded by LOG-0065: the old basis was
"the original asset is unreachable", which is a statement about one file by one
route, not about inheritance. LOG-0065 put the surrogate route at HYPOTHESIS,
confidence 0.6 — plausibility of the route, explicitly not of its working. This
experiment is what replaces that estimate with a measurement.
