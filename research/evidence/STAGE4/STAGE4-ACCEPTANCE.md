# STAGE 4 — manifests and mod discovery

**Verdict: PASS.** Dropping self-describing mod folders into a discovery root is
sufficient for the framework to identify, validate, order and load them, with no
hardcoded per-mod knowledge anywhere in the framework or in the acceptance.

**Build:** `misery-24953925-ue5.4.4-bace50f7185d`, UE **5.4.4** CL **35576357**.

## The tree that was actually loaded

```text
D:/UEScratch/ModsRoot/
├─ ZZ_AlphaMod_v1/          mod_id: alphamod
│  ├─ mod.json
│  ├─ Content/Mod_alphamod_P.{pak,utoc,ucas}
│  └─ Code/items.py
└─ aa-beta-mod/             mod_id: betamod   (depends on alphamod ^1.0.0)
   ├─ mod.json
   ├─ Content/Mod_betamod_P.{pak,utoc,ucas}
   └─ Code/items.py
```

The folder names are deliberately unlike the ids, differently cased, and sort in
the opposite order to the load order. If any layer ever started keying off the
folder name the acceptance fails at once instead of in a user's install later.

## Manifest schema (version 1)

```json
{
  "manifest_version": 1,
  "mod_id": "alphamod",
  "name": "alphamod (Stage 4 fixture)",
  "version": "1.0.0",
  "framework_api": "^0.4.0",
  "content": ["Mod_alphamod_P"],
  "code": ["items.py"]
}
```

Plus optional `dependencies`, `optional_dependencies`, `conflicts`. Every field
has a Stage 4 consumer that would break without it. Author, description,
licence, homepage, tags and load-order hints are **absent** — a schema field
nothing consumes is a field nobody validates and everybody eventually trusts.

`manifest_version` is read **first and alone**: every other field's meaning is
defined by it, so a future manifest is refused by number rather than judged
against today's grammar. Unknown fields are refused, not ignored, so a typo like
`"dependancies"` cannot silently disable what the author meant.

## Layer separation

| layer | file | needs a game? |
| --- | --- | --- |
| discovery | `tools/modframework/discovery.py` | no |
| validation | `tools/modframework/manifest.py` | no |
| arbitration | `tools/modframework/resolve.py` | no |
| execution | `tools/modframework/execution.py` + the live acceptance | only the last step |

The first three are proven by **62 offline tests** with no MISERY, no Unreal and
no containers. That is the architectural claim, not a convenience.

## Results

* **Offline acceptance** — 35 checks, 35 passed.
* **Live acceptance** — **69 checks, 69 passed**
  (`stage4-live-acceptance.json`).
* **Unit tests** — 80 for Stage 4 (62 written up front, 18 added as regressions
  for the adversarial review below); full repository suite **2331 passed**,
  1 skipped, validator exit 0.

### What the live run proved

1. **Both discovered and validated** from the tree; no folder name equals the
   mod_id it holds.
2. **Deterministic order** — identical plan across *every* permutation of the
   discovered set and across 8 shuffled filesystem enumerations, and the order
   honours the dependency graph (`alphamod` before `betamod`).
3. **Content mounted** — each declared container is mounted *and* its packages
   registered, read as two separate facts, with the bare `CT03Probe` pak as the
   control proving the second signal discriminates.
4. **Assets distinct** — no two mods share a mesh object, an icon object, or a
   material instance.
5. **Items registered under their own ModId** — both mods declare the same
   `local_id` (`shape`) and produce `alphamod__shape` and `betamod__shape`. Each
   mod's mesh slots resolve only to materials in its own namespace, and every
   slot parent to a real vanilla material.
6. **Selective unload** — unregistering `alphamod` left every `betamod` row
   present, and `betamod`'s mesh, slots and materials were **re-read from the
   live process** afterwards and were unchanged. "Intact" is checked, not
   inferred from a row still being listed.
7. **Baseline restored** — `MasterItemList`, `ItemList`, `ParentTables.Num`,
   subscription count all back; aggregate unrooted; asset store owns nothing.
8. **Negative fixtures** — ten broken mods in one tree alongside a healthy one:
   every one of the nine required failure classes is reported, none reached the
   load plan, no excluded mod carries a manifest in the plan, and the execution
   layer produced declarations only for planned mods.

## Fail-closed decisions, stated plainly

* **Duplicate `mod_id` refuses BOTH claimants.** "First on disk" is not a
  decision anybody made — not the user, not the authors — and it changes when a
  folder is renamed. An ambiguous identity is refused, not resolved. A test
  renames the folders to reverse their order and requires the outcome unchanged.
* **An explicit conflict refuses both sides.** Which of two mods that declare
  they cannot coexist should win is a question only the user can answer.
* **Exclusion propagates transitively.** Every mod in `load_order` has all of its
  required dependencies in `load_order`, ahead of it — asserted directly.
* **A present-but-incompatible optional dependency is fatal.** The author said
  "if this is here, I need this version"; running against a version they
  excluded is worse than not running.
* **A mod is fully in or fully out.** Artifact checks drop the manifest at
  discovery, so a half-present mod never reaches the resolver looking whole.

## Identity is enforced, not trusted

`mod_id` is the authoritative namespace. Two mechanisms make that structural:

* A mod's **code cannot name a namespace**. `item_definitions()` returns data
  with a `local_id`; the execution layer attaches `mod_id` from the *manifest*. A
  declaration containing `mod_id` is refused rather than ignored.
* A mod's **declared content must be its own**. The container is read back and
  any package path belonging to another mod is `content_namespace_mismatch`.
* Declared artifact paths may not be absolute or contain `..`.

## Adversarial review: 14 candidates, 10 confirmed, 4 refuted

After the acceptance passed at 69/69, four independent reviewers attacked the
resolver from separate lenses -- determinism, fail-closed guarantees, identity,
and version parsing -- and every candidate finding was then handed to a
different reviewer whose instruction was to *refute* it. Ten survived. All ten
are fixed, each with a regression test; evidence in `adversarial-review.json`.

Every one of these was found against a suite that was **fully green at the
time**. Recorded in the order of how much they mattered:

1. **Case-colliding folders failed OPEN** (`discovery.py`). Two folders whose
   names differ only in case held two *unrelated* mods. The code refused only
   the one it met second, leaving the first accepted — so which mod loaded was
   decided by which folder name sorted first by codepoint, and flipping one
   letter's case flipped which mod reached the live plan. That is the folder
   name deciding identity, the exact thing this stage forbids, and it failed
   open. Now every member of a colliding group is refused, as the duplicate
   rule already did. The module docstring had *described* the correct behaviour
   all along; the code did the opposite.
2. **A duplicate paired with any other failure was never reported as a
   duplicate** (`resolve.py`). Duplicates were counted only over manifests that
   fully validated, so a broken twin was filed under its own id as "malformed" —
   which then evicted the *healthy* owner of that id through the shared
   exclusion map, under a code naming the wrong problem. Grouping is now by the
   id a folder **claimed**, so claiming an id is enough to be a claimant.
3. **A mod could partially reach the execution plan** (`execution.py`). A mod
   whose code emitted one illegal declaration still contributed its others. That
   is precisely the "partially accepted mod" the stage forbids. A mod is now
   accepted whole or not at all.
4. **A container stem was an unowned namespace** (`manifest.py`). Stems share
   one staging directory, so a mod could declare another mod's stem and
   overwrite its container. Stems must now be namespaced by `mod_id`.
5. **`local_id` was never validated** (`execution.py`). A row name Stage 2
   cannot own could be published — and one containing `__` would decompose to a
   *different* mod. It is now held to the same rule as `mod_id`.
6. **One bad manifest could abort the entire scan, twice over.**
   `sorted()` over a set that could contain `None` raised `TypeError`
   (`ns.owning_mod` returns `None` outside `/Game/Mods`), and a version
   requirement containing an internal newline raised `AttributeError` because
   the regex returned `None`. Neither is a `VersionError`, so both escaped every
   caller and left *no plan for any mod*. Both now fail as one mod's diagnostic.
7. **A dependency with no `version` silently meant `^0.0.0`** (`manifest.py`) —
   "major must be 0" — so it refused every dependency at 1.0.0 or later while
   reading like "any version". A version is now required; `>=0.0.0` says "any".
8. **The cycle diagnostic named edges that do not exist** (`resolve.py`). It
   joined the *alphabetically sorted* component with `->` and presented it as
   the dependency chain, so a cycle `a -> c -> b -> a` was reported as
   `a -> b -> c -> a`, sending anyone debugging it to the wrong manifest. It now
   reports the members and the edges that actually exist.

The four refuted claims are kept in the evidence too. One is worth naming: a
reviewer argued that two case-colliding folders declaring the **same** mod_id
also fail open. They do not — that path fails closed for an unrelated reason,
and the refuting reviewer demonstrated it rather than asserting it.

## Defects found and fixed during development

1. **Cross-stage identity inconsistency (real, pre-existing).** Stage 3's
   `namespace.check_mod_id` accepts `has__separator`; Stage 2's `ItemId` refuses
   it, because `<mod_id>__<local_id>` would be ambiguous to decompose. Each rule
   is correct on its own terms. `mod_id` is used by both, so what a mod may
   actually be called is the **intersection**, and Stage 4 — the layer that owns
   identity across both — now enforces it. Neither Stage 2 nor Stage 3 was
   changed. A test asserts Stage 4's rule stays at least as strict as both and
   that its separator still matches the one Stage 2 actually uses.
2. **The load plan recorded exclusions but lost their reasons.** `plan.excluded`
   named every refused folder while `plan.diagnostics` carried only the
   resolver's own findings — discovery-time reasons (malformed manifest,
   unsupported version, bad artifact) were dropped. A plan that cannot say *why*
   a mod is missing is the untrustworthy artefact this stage exists to avoid.
   Found by the negative-fixture acceptance, not by a unit test.
3. **Module shadowing, again.** `tools/modframework/fixtures.py` collided with
   `tools/modkit/fixtures.py`; whichever path was inserted last won, and every
   Stage 4 test failed on a missing attribute from the wrong module. Renamed to
   `treefixtures.py` — the same defect class that once shadowed
   `tools/kb/validate.py`. Distinct names are the fix; import order is not.
4. **An over-strict acceptance check.** The negative run required the healthy mod
   to be the *only* survivor, but one negative fixture legitimately contains a
   valid mod (the provider whose consumer asks for an impossible version).
   Demanding an exact list called the resolver wrong for doing the right thing.

## Scope

* Staging is now **computed from the load plan**
  (`research/instruments/mods/stage_from_plan.py`) rather than hand-maintained.
  Containers predating Stage 4 are carried in an explicit `LEGACY_*` list with a
  stated reason each, so `expect` remains an exact allow-list.
* Stage 3's pipeline was **not** redesigned. Its output is consumed through
  manifest-declared content.
* Unsupported material capabilities remain exactly as Stage 3 left them —
  emissive, custom shader graphs, WPO, blend mode and subsurface are explicit
  diagnostics, untouched by this stage.
* **Not started:** Stage 5 production Steam/bootstrap loading, Stage 6 surrogate
  Blueprint inheritance. The discovery root is a parameter; making the game read
  `<install>/Mods` automatically at launch is Stage 5's job. The installation
  stays read-only.
* Importing a mod's code module **executes it**. That is inherent to code mods.
  Modules load in plan order under names derived from the mod_id so two mods
  shipping `items.py` cannot collide, and a module that raises removes only its
  own mod from the run.
