# Stage 8 — Developer Platform Foundations: architecture and acceptance plan

Written before implementation. The headline finding is that this stage is
mostly a **port**, not a design.

## 1. What already exists

Stage 4.5 designed all eight primitives at the ABI level and shipped **tested
Python reference implementations** of most of them. `MiseryBridge.h` already
declares capability tables for log, events, settings, input, services, items,
console, diagnostics and host, each with `struct_size` + version negotiation.

| primitive | contract | native implementation | reference |
| --- | --- | --- | --- |
| 1 Logging | `IModLog`, `MbLogTable` | **done** | `modlog.py` (214) |
| 2 Structured errors | `ModSubsystem`×`ModErrorCode`, `MB_SUB_*`×`MB_E_*`, `ModException.Is()` | **done numerically** | `errors.py` (169) |
| 3 Dev console | `MbConsoleTable` declared | **absent, not even dispatched** | `console.py` (282) |
| 4 Settings | `IModSettings`, `SettingKey<T>` | `declare` only; 9 accessors `nullptr` | — |
| 5 Services | `MbServicesTable` | publish/bind/is_available; `call`+`release` `nullptr` | `services.py` (200) |
| 6 Lifecycle/ownership | ownership core, epochs, `mod_is_reclaimable` | **done and proven** | `BridgeCore.h` |
| 7 Version/capabilities | `ModApi.Version`, `ICapabilityGrant` | **done** | `capabilities.py` (173) |
| 8 Snapshot | `MbDiagnosticsTable.snapshot_json` | partial | `console.py` builtins |

`console.py` already implements builtins for **mods, errors, items, services,
capabilities** plus help/commands/log/settings. Of the six commands the brief
names, only **`generations`** has no reference — it postdates Stage 4.5.

### The discipline this implies

Stage 5B Step 4 ported Stage 4's planner into the runtime and proved it was a
port and not a fork by **differential testing** against the Python original.
Stage 8 uses the same method: the Python reference is the oracle, and a
differential harness feeds identical inputs to both and requires identical
outputs. That is what stops the runtime quietly acquiring different semantics
from the tested reference.

## 2. Decisions

Six contract decisions went through Tier-A review with an adversarial critique
pass. **Five were flagged fatal as written.** What follows is the amended form.

### D1 — Logging: change nothing in the API

`IModLog` and `MbLogTable` stay byte-for-byte. `Warn` is **kept**, and
`Warning` is not added. The name is pinned in three mirrors —
`MB_LOG_WARN`, `modlog.WARN`, `ModLogLevel.Warn` — and the agreement is
machine-enforced by `tests/test_bridge_contract.py`, which derives the C# member
name from the C one by capitalisation. The brief's "Debug/Info/Warning/Error"
names four severities, not four identifiers; all four exist, plus `Trace`.

Adding `Warning()` later is a *minor* bump with exactly one implementer, so the
cheap door stays open. Renaming `Warn` later is a *major* bump requiring every
mod to rebuild — deciding "keep" now closes the expensive door for free.

What Stage 8 does add: the record semantics from `modlog.py` — message cap,
per-mod budget with one drop notice per window, framework metadata in record
slots rather than in the mod's field map, and limits that never throw. Scoped
loggers are deferred: `fields["scope"]` already expresses it, and a child logger
object would raise four ownership questions in the stage whose ownership model is
supposed to be frozen.

### D2 — Error codes: a derived projection, never a second identity

No new registry-numbered string space. `errors.py` already ships
`code_name(subsystem, code)` producing `settings.not_found`,
`lifecycle.reentrant_unload`. Stage 8 formalises that dotted form as a **total
pure projection** of the existing `(ModSubsystem, int)` pair: derived at display
time, never stored, never a constructor parameter, never on the wire. One fact,
one rendering — nothing that can drift.

`ModException.Is(string)` is **not** added; string matching on an identity that
is derived would invite exactly the drift the projection avoids.

Critique amendment adopted: a new `Mod` subsystem must land in **all three**
mirrors (header, Python, C#) or `test_bridge_contract.py`'s three-way equality
test fails. The test compares C# by regex over source text, so any "deliverable
test" that claims to call into C# is not implementable as specified.

### D3 — Console: `misery:` is the framework namespace, not `mbpl`

`mbpl` is **not** reserved and must not be: it is an ordinary `mod_id`, and
reserving it would break existing item definitions. Framework commands are
`misery:<name>`; a mod's commands are `<mod_id>:<name>`, derived from the record
exactly as log `mod_id` is, so two mods cannot collide and no mod can claim
another's namespace.

Handlers do not cross the ABI as delegates — the established rule. The console
reuses the **events trampoline** pattern already proven for dispatch, and a
registered command is an owned resource on the existing ledger, revoked by the
same teardown as everything else.

`run()` is host-only. Commands execute on the game thread, because framework
commands read live state.

Critique amendments adopted, all pre-implementation:
- **`Escape()` must be replaced before anything new writes JSON.** It escapes
  only `"`, `\` and `\n` and passes every other control byte 0x00–0x1F through
  raw, which RFC 8259 forbids. This is a **live defect today**: the diagnostics
  snapshot already renders mod-supplied text through it.
- **The result cap fails open.** `StringArena::Put` returns the literal
  `"<detail too long>"` past 64 KB, so an oversized envelope would return
  `MB_STATUS_OK` with a non-JSON body. A cap must be enforced *before* the
  arena, and overflow must be a structured failure.
- The envelope is `console.py`'s exactly — `{"ok", "command", "result"|"error"}`
  — with no invented `"text"` key, so its `render()` keeps working.

### D4 — Services: a native call frame, and `bind` must stop lying

`bind()` currently ignores its version requirement. A mod can bind `">=2.0.0"`
against a 1.0 provider and be told it succeeded. That is a contract lie and is
fixed first; `services.py` already enforces it and already reports the mismatch
as `SUB_SERVICES` × `E_INVALID_ARGUMENT`, so the code is **not** new.

Calls become a **call frame**: `call_begin`/`call_end` bracket the invocation so
it registers in `active_frames`, which `IsReclaimable` already refuses to
reclaim across. Args and results are JSON by method name; no delegate and no
managed `Type` crosses, which also keeps services immune to cross-ALC type
identity problems.

The provider-revoked-mid-call TOCTOU is **already solved** by the existing core:
`Dispose` revokes before releasing, so the epoch bump invalidates the slot and a
nested call fails closed. The binding must therefore hold the **service handle,
not the name** — resolving by name at call time is the re-lookup that reopens
the race. This is the same defect shape as the 2026-09-01 resolver crash.

Critique amendment adopted: no `MB_E_VERSION_MISMATCH`. Reuse
`E_INVALID_ARGUMENT` as the Python reference already does, and do not introduce a
services-local code `1`, which `code_name` would render as `not_initialised`.

### D5 — Settings: per-mod JSON outside the installation

Location `%LOCALAPPDATA%\MISERY\Saved\MiseryFramework\Settings\`, resolved once
at bootstrap and injected the way the items backend already is — never
hardcoded, and never under the installation, which is read-only except the
bootstrap surface.

Framework-owned envelope carrying `format` plus nested `values`; per-mod
namespacing on disk; **per-key type validation instead of migrations**, so a
stored value whose type no longer matches its declaration is refused and the
default used, with a structured warning. Atomic replace on save. Typed
`get_*`/`set_*` pairs are kept over a JSON blob, matching the existing table.

Critique amendments adopted — both were genuine faults:
- "Do not offer `core.settings`" would **take down the whole managed host**:
  `HostController`'s constructor acquires it unconditionally.
- Auto-flush on the release path would write to disk from **teardown**,
  including for mods that **failed** — `HostModFailed` runs the same teardown as
  unload. Persistence must not ride the reclaim path.

### D6 — Snapshot: host-only, closed-field, structurally redacted

`DiagSnapshot` stays as it is. The support bundle is a **new** host-only
document at table v1.1 with a **closed field list** — an allowlist, not "dump
what we have".

Redaction is **structural, not opt-in**. This project has already published
`MachineId`, `LoginId` and `EpicAccountId` once by committing a raw UE
`CrashContext`; that is recorded in `research/evidence/CRASH-2026-09-01/`. A
bundle is meant to be pasted into a bug report, so machine identifiers, account
identifiers, user names and absolute user paths must be **impossible to add**,
not merely absent by default. The build fingerprint is the game's `build_key`,
which identifies the *game*, not the machine.

Recent errors: one global bounded ring. Critique amendments adopted, and they
matter:
- **A ring written at `Fail()` is a data race** — `Fail()` demonstrably runs on
  non-game threads, including from `BRIDGE_ENTER`'s own wrong-thread branch.
  This is the 2026-09-01 defect class exactly. It needs a mutex covering the
  ring, or it must not be written there.
- `SetContentGeneration` would be called from the **runtime** thread, since
  `content::Publish` runs in the polling loop — so a naive push path reintroduces
  the pull path's problem.
- `record_error` cannot record the wrong-thread error it names, because it sits
  behind `BRIDGE_ENTER` itself.

## 3. Public API shape

Deliberately small. Most of Stage 8 is implementation behind contracts that
already exist.

**Unchanged:** `IModLog`, `ModLogLevel`, `IModSettings`, `SettingKey<T>`,
`IModServices`, `IModService`, `ICapabilityGrant`, `IModEvents`, `IModResource`,
`ModException`. `ModApi.Version` stays `0.5.0`.

**Added, additively:**

```csharp
// Console — a mod registers commands it owns; the name is namespaced from the
// record, so a mod cannot claim another's.
public interface IModConsole {
    IModResource RegisterCommand(string localName, string summary,
                                 Func<ConsoleInvocation, string> handler);
}
public readonly struct ConsoleInvocation {
    public string Command { get; }        // fully qualified, "<mod_id>:<name>"
    public string ArgumentsJson { get; }
}

// Diagnostics — a mod may read its OWN state; the bundle is host-only.
public interface IModDiagnostics {
    string OwnStateJson { get; }
    bool IsReclaimable(out string reasonJson);
}

// Introspection — the active generation, typed, no engine concept exposed.
public interface IModContext {                    // additions only
    bool TryGetConsole(out IModConsole console);
    bool TryGetDiagnostics(out IModDiagnostics diagnostics);
    ContentGeneration Generation { get; }         // { ulong Id; string Phase; }
}

// Settings — one addition to an existing type.
public sealed class SettingDeclaration {
    public static SettingDeclaration Of<T>(string key, T defaultValue,
                                           string description = null);
}
```

Nothing here names a `UObject`, `FName`, `ProcessEvent`, or an address.

## 4. Acceptance criteria

Fixed before implementation. Each is a separate fact.

1. **The port is a port.** A differential harness feeds identical inputs to the
   Python reference and the runtime for logging records, error-code projection,
   console dispatch and service binding, and requires identical outputs.
   Divergence is a failure, not a note.
2. **`Escape()` is RFC 8259 correct**, proven by a test that round-trips every
   byte 0x00–0x1F plus `"`/`\`/DEL through a real JSON parser.
3. **No declared API can crash the game.** Every table slot that is `nullptr`
   is either implemented or its managed caller throws a structured
   `ModException`; a test enumerates the tables and asserts no reachable
   `nullptr`.
4. **`bind` enforces its requirement**, and a mismatch returns
   `SUB_SERVICES`×`E_INVALID_ARGUMENT` with the versions in the detail.
5. **A call keeps its provider alive.** With a call in flight,
   `mod_is_reclaimable` is false for the provider; after it returns, true.
6. **A revoked provider fails a bound consumer closed** — the consumer's next
   call returns a structured error and does not dereference anything.
7. **Commands are owned.** A mod's commands vanish from `misery:commands` when
   it unloads, and its ALC still becomes reclaimable.
8. **Settings survive a restart**, are per-mod namespaced on disk, and a
   type-changed key falls back to its default with a structured warning rather
   than throwing.
9. **Settings are never written from teardown**, including for a failed mod —
   asserted by a test that fails a mod and checks no file appeared.
10. **The bundle cannot contain identifiers.** A test asserts the emitted
    document contains no `MachineId`, `LoginId`, `EpicAccountId`, user name or
    absolute user path, and that the field list is an allowlist.
11. **The bundle states the required facts**: build fingerprint, framework
    version, loaded and failed mods, active generation, capabilities, registered
    resources/items/services/commands, recent structured errors.
12. **Thread safety is proven, not assumed.** The error ring is exercised from
    multiple threads under a harness; the 2026-09-01 guard pattern applies.
13. **One broken mod beside it changes none of the above** — the standing
    isolation invariant, re-checked with the existing broken fixtures.
14. **The suite stays green** and the three-way contract mirror
    (header / Python / C#) still passes.

## 5. Live defects found while planning

Independent of Stage 8, present now:

- **`Escape()` produces malformed JSON** for control bytes. Affects the
  diagnostics snapshot and every error detail today.
- **`services.bind` ignores its version requirement** and reports success.
- **`StringArena::Put` fails open** past 64 KB, returning a non-JSON literal
  under `MB_STATUS_OK`.

## 6. Not in Stage 8

No multiplayer. No settings UI. No Player/World/Combat research. No gameplay
mechanics. No input registry — `MbInputTable` stays declared and undispatched;
it is not one of the eight primitives.
