#!/usr/bin/env python3
"""Stage 7: the reference mod, end to end on the production framework.

    Steam Play
      -> discover the real mod folder
      -> deterministic load plan
      -> mount mod content
      -> load the mod's own Blueprint world class
      -> C# OnLoad
      -> declare an item with that class
      -> P1 validates real BP_StaticMasterItem ancestry
      -> SGK ItemDetails resolves the item
      -> P2 grants the declared item to the live player inventory
      -> verify the game actually accepted it
      -> clean shutdown

WHAT THIS INSTRUMENT MAY AND MAY NOT KNOW
-----------------------------------------
It names the mod, because an acceptance has to say what it is driving. The
FRAMEWORK may not, and tests/test_no_mod_specific_core.py enforces that
separately by grep. The two halves of the boundary are checked in different
places on purpose: a guard living in the thing it guards is not a guard.

P2 IS VERIFIED BY DIFFERENTIAL, NOT BY RETURN VALUE
---------------------------------------------------
The API returns how many the inventory took. Believing it would be testing the
framework against its own account of itself. So the player's inventory is read
before and after, out of process, and the delta must be exactly the row that was
granted -- and the game's own refusal, if the pack is full, is a legitimate
outcome rather than something to force.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
for _p in (os.path.join(REPO, "research", "instruments", "eri"),
           os.path.join(REPO, "research", "instruments", "runner"),
           os.path.join(REPO, "research", "instruments", "ipp"),
           os.path.join(REPO, "research", "instruments", "mods"),
           os.path.join(REPO, "tools", "modplatform"),
           os.path.join(REPO, "tools", "modkit")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import eri                                                       # noqa: E402
import install as installer                                      # noqa: E402
import nativebuild as nb                                         # noqa: E402
import stage5b_bindings as sb                                    # noqa: E402
import stage5b_resolver_lifecycle as sweep                       # noqa: E402

MOD_ID = "refmod"
MOD_SOURCE = os.path.join(REPO, "reference", MOD_ID)
CONTAINER = "Mod_%s_P" % MOD_ID
ASSEMBLY = "RefMod.dll"
EXPECTED_ROW = "refmod__sample"
WORLD_CLASS = "/Game/Mods/refmod/Blueprints/BP_WorldItem.BP_WorldItem_C"
WORK = r"D:\UEScratch\Stage7"


# The runner reports a blocked entry in its JSON, not on stderr.
BLOCKED_REASON = re.compile(r'"blocked_reason":\s*"(.*?)"(?:,|\n|\})', re.S)


def build_managed():
    for project in (os.path.join(REPO, "managed", "Misery.ModAPI"),
                    os.path.join(REPO, "managed", "Misery.ModHost"),
                    os.path.join(MOD_SOURCE, "Code")):
        result = subprocess.run(["dotnet", "build", "-v", "quiet", "--nologo"],
                                capture_output=True, text=True, cwd=project,
                                timeout=900)
        if result.returncode != 0:
            raise SystemExit("%s failed to build:\n%s"
                             % (project, result.stdout[-3000:]))


# The save the runner is configured to load, and the files that ARE that save.
# SaveGameMetaData.sav is shared by every slot and decides the row the entry
# machine clicks, so it belongs to the controlled state too.
CONFIGURED_SLOT = "123"
# How long each pass stays in the world before its inventory is read. Equal on
# every side by construction, so the comparison is between like and like.
DWELL_SECONDS = 90.0
SNAPSHOT_DIR = os.path.join(WORK, "save-snapshot")
BACKUP_DIR = os.path.join(WORK, "save-backup-original")


def save_files():
    """Absolute paths of the tracked save files that exist right now.

    Deliberately narrow. Everything else in SaveGames belongs to the person
    whose machine this is -- other slots, control bindings, settings -- and this
    instrument does not get to write over any of it.
    """
    import saves                                                   # noqa: PLC0415
    names = ("%s.sav" % CONFIGURED_SLOT, "%s_Auto.sav" % CONFIGURED_SLOT,
             "SaveGameMetaData.sav")
    return [os.path.join(saves.SAVE_DIR, n) for n in names
            if os.path.isfile(os.path.join(saves.SAVE_DIR, n))]


def hash_saves():
    """{filename: sha256} for the tracked save files, as they are on disk."""
    digests = {}
    for path in save_files():
        with open(path, "rb") as handle:
            digests[os.path.basename(path)] = hashlib.sha256(
                handle.read()).hexdigest()
    return digests


def copy_saves(dest):
    os.makedirs(dest, exist_ok=True)
    for path in save_files():
        shutil.copy2(path, os.path.join(dest, os.path.basename(path)))
    return sorted(os.path.basename(p) for p in os.listdir(dest))


def restore_saves(source):
    """Put the snapshot back, and verify byte-for-byte that it took.

    WHY THIS EXISTS
    ---------------
    The differential compares two launches of the same save. "The same save"
    was previously only "the same row in the load menu", which says nothing
    about the bytes behind it: a manual session, an autosave, or anything else
    touching that slot between the passes would be measured as if the mod had
    caused it. Restoring a recorded snapshot before EACH side, and hashing it,
    makes the input a controlled quantity instead of an assumption.
    """
    import saves                                                   # noqa: PLC0415
    written = []
    for name in sorted(os.listdir(source)):
        target = os.path.join(saves.SAVE_DIR, name)
        shutil.copy2(os.path.join(source, name), target)
        written.append(name)
    return written


# Mods installed BESIDE the reference mod, to prove it is unaffected by them.
#
# Both are Stage 5A fixtures in the sense that matters: they are real mods, in
# real mod folders, that the production discovery admits and the host tries to
# load. ThrowOnLoadMod fails during OnLoad. ThrowOnContentReadyMod loads and then
# throws from inside misery:content_ready -- the dispatch path Stage 7 itself
# added, where a second subscriber could otherwise deny the first its event.
# The readiness adversary's id sorts BEFORE "refmod" deliberately. Mods load in
# mod_id order, subscribers are dispatched in registration order, so an id after
# "refmod" would put the throwing handler last and the test would prove nothing:
# the reference mod would already have been notified before anything went wrong.
BROKEN_NEIGHBOURS = (
    ("brokenreadymod", "ThrowOnContentReadyMod"),
    ("throwonloadmod", "ThrowOnLoadMod"),
)


def tree_manifest(root):
    """{relative path: sha256} for every file under root.

    The installation is supposed to come back to exactly what it was. "Supposed
    to" is what a manifest is for: the framework writes into the game's own
    Binaries directory, and that is the one place this project has promised to
    leave alone apart from a single named bootstrap file.
    """
    out = {}
    for base, _dirs, files in os.walk(root):
        for name in files:
            path = os.path.join(base, name)
            try:
                with open(path, "rb") as handle:
                    digest = hashlib.sha256(handle.read()).hexdigest()
            except OSError as failure:                             # noqa: PERF203
                digest = "unreadable: %s" % failure
            out[os.path.relpath(path, root).replace(os.sep, "/")] = digest
    return out


def mod_spec():
    """The mod's own Mod Kit spec -- the one source for what it ships."""
    with open(os.path.join(MOD_SOURCE, "modkit.json"), encoding="utf-8") as handle:
        return json.load(handle)


def declared_parent():
    """The game class the mod's Blueprint says it derives from.

    Read from the mod's spec rather than written here a second time: this is the
    value the Mod Kit cooked against, so a copy in the instrument could agree
    with nothing and still look right.
    """
    blueprints = mod_spec().get("blueprints") or []
    if len(blueprints) != 1:
        raise SystemExit("expected exactly one blueprint in the mod spec")
    return blueprints[0]["parent"]           # "/Game/....BP_StaticMasterItem_C"


def framework_names_in(dll_path):
    """Every "Misery.*" name that appears anywhere in the mod's assembly.

    A CONSERVATIVE check, and worth being clear about what it is: this scans the
    file's ASCII strings rather than decoding the AssemblyRef table, so it can
    over-report (a string literal would count) but it cannot miss a reference --
    an assembly the mod is linked against has its name in the metadata heap. So
    "the only framework name in this file is Misery.ModAPI" is a real, if blunt,
    statement that the mod is built on the public API alone.
    """
    import re                                                      # noqa: PLC0415
    with open(dll_path, "rb") as handle:
        raw = handle.read()
    return sorted({m.decode("ascii")
                   for m in re.findall(rb"Misery\.[A-Za-z0-9_.]+", raw)})


def class_objects_named(objects, name):
    """Live UClass objects with this exact name -- classes, not instances."""
    out = []
    for address, record in objects.items():
        if not record.get("valid") or record.get("name_text") != name:
            continue
        kind = (objects.get(record.get("class_ptr") or 0) or {}).get("name_text")
        if kind in ("BlueprintGeneratedClass", "Class"):
            out.append(address)
    return out


def newest(root, filename, beside=()):
    """The most recent `filename` under root -- from an OUTPUT directory.

    `obj/` holds copies the compiler makes for its own purposes, among them the
    ref/ and refint/ reference assemblies: real files with the right name, and
    no deps.json, runtimeconfig.json or dependencies beside them. On 2026-09-01
    one of those won an mtime tie by 0.0006s, three files silently vanished from
    the install, and the game refused to start the managed host with
    hostfxr_initialize_for_runtime_config 0x80008093 -- correct behaviour, a
    long way from the cause, and half an hour of a live run wasted.

    So intermediates are skipped, and `beside` names files that must sit in the
    same directory: that makes "this is an output directory" something the
    function CHECKS rather than something the caller hopes.
    """
    found = []
    for base, _dirs, files in os.walk(root):
        if "obj" in os.path.normpath(base).lower().split(os.sep):
            continue
        if filename in files and all(name in files for name in beside):
            found.append(os.path.join(base, filename))
    if not found:
        raise SystemExit("%s was not produced under %s%s"
                         % (filename, root,
                            (" beside %s" % ", ".join(beside)) if beside else ""))
    return max(found, key=os.path.getmtime)


def install_neighbours(install_root):
    """Add the broken mods beside the reference mod, as real mod folders.

    Written into the SAME Mods tree the production discovery scans, with their
    own mod.json and their own Code directory, so nothing about how they are
    found differs from the reference mod.
    """
    added = []
    for mod_id, assembly in BROKEN_NEIGHBOURS:
        source = os.path.join(REPO, "managed", "fixtures", assembly)
        built = os.path.dirname(newest(source, assembly + ".dll",
                                       beside=(assembly + ".runtimeconfig.json",)))
        mod_dir = sb.fc.framework_path(install_root,
                                       os.path.join("Mods", assembly))
        code_dir = os.path.join(mod_dir, "Code")
        os.makedirs(code_dir, exist_ok=True)
        for name in os.listdir(built):
            if name.endswith((".dll", ".json")) and not name.startswith("Misery."):
                shutil.copyfile(os.path.join(built, name),
                                os.path.join(code_dir, name))
        manifest = {"manifest_version": 1, "mod_id": mod_id,
                    "name": assembly, "version": "1.0.0",
                    "framework_api": "^0.4.0", "code": [assembly + ".dll"]}
        with open(os.path.join(mod_dir, "mod.json"), "w",
                  encoding="utf-8", newline="\n") as handle:
            json.dump(manifest, handle, indent=2, sort_keys=True)
            handle.write("\n")
        added.append(mod_id)
    return sorted(added)


def install_everything(install_root):
    """Framework, managed host, and the reference mod as a real mod folder."""
    proxy, runtime = sb.build_everything()
    profile = sb.real_profile(install_root)
    sb.fc.close_game()

    staging = os.path.join(WORK, "payload")
    if os.path.isdir(staging):
        shutil.rmtree(staging)
    mod_dir = os.path.join(staging, "Mods", "ReferenceMod")
    code_dir = os.path.join(mod_dir, "Code")
    content_dir = os.path.join(mod_dir, "Content")
    os.makedirs(code_dir)
    os.makedirs(content_dir)

    # The host is only a host with its runtime config and the API beside it;
    # requiring them here is what makes the directory the right one.
    host_dir = os.path.dirname(newest(os.path.join(REPO, "managed",
                                                   "Misery.ModHost"),
                                      "Misery.ModHost.dll",
                                      beside=("Misery.ModHost.runtimeconfig.json",
                                              "Misery.ModAPI.dll")))
    for name in os.listdir(host_dir):
        if name.endswith((".dll", ".json")):
            shutil.copyfile(os.path.join(host_dir, name),
                            os.path.join(staging, name))
    shutil.copyfile(os.path.join(nb.DOTNET_PACK, "nethost.dll"),
                    os.path.join(staging, "nethost.dll"))

    code_src = os.path.dirname(
        newest(os.path.join(MOD_SOURCE, "Code"), ASSEMBLY,
               beside=(ASSEMBLY.replace(".dll", ".runtimeconfig.json"),)))
    for name in os.listdir(code_src):
        if name.endswith((".dll", ".json")):
            shutil.copyfile(os.path.join(code_src, name),
                            os.path.join(code_dir, name))
    built = os.path.join(r"D:\UEScratch\ModKitBuild", MOD_ID, "container")
    for suffix in (".pak", ".utoc", ".ucas"):
        source = os.path.join(built, CONTAINER + suffix)
        if os.path.isfile(source):
            shutil.copyfile(source, os.path.join(content_dir,
                                                 CONTAINER + suffix))
    shutil.copyfile(os.path.join(MOD_SOURCE, "mod.json"),
                    os.path.join(mod_dir, "mod.json"))

    # The framework's Mods tree is replaced so a previous run's mods cannot
    # change this one's plan.
    stale = sb.fc.framework_path(install_root, "Mods")
    if os.path.isdir(stale):
        shutil.rmtree(stale)
    payload = {"MiseryRuntime.dll": runtime}
    for base, _dirs, files in os.walk(staging):
        for name in files:
            absolute = os.path.join(base, name)
            payload[os.path.relpath(absolute, staging)] = absolute
    installer.install(install_root, proxy, payload)
    sb.put_profile(install_root, profile)
    return sorted(payload)


def read_inventory(inv):
    """Every item id in the LIVE PLAYER's inventory, counted.

    WHICH object is the player's inventory is not decided here, and is not taken
    from the framework either: `readiness.prove_gameplay` already answers it,
    and it is the same answer the gameplay phase itself is defined by. Asking
    the thing under test where to look would not be a measurement.

    The first version of this function looked for objects whose class was NAMED
    BP_MasterInventory_C. The player's inventory is a BP_PlayerInventory_C --
    two links further down the chain (BP_PlayerInventory_C ->
    BP_EquipmentInventory_C -> BP_MasterInventory_C) -- so that reading counted
    1683 crates, scaffolds and car boots while excluding the only inventory the
    question was about. It also filtered on the inventory being outered to the
    pawn; it is outered to BP_SGKController_C.

    `inv` is the inventory section of the binding profile, resolved by the
    caller: this must work in a session with no framework installed.

    Returns {row_name: count}, or None when there is no live player inventory to
    read -- which is a different answer from "empty" and is kept distinct.
    """
    import cr01c3_recon as recon                                   # noqa: PLC0415
    import lifecycle                                               # noqa: PLC0415
    import readiness                                               # noqa: PLC0415

    if len(lifecycle.find_processes()) != 1:
        return None
    api = eri.Win32Api()
    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    handle = eri.open_process_read_only(api, i01["pid"])
    try:
        namepool, objects = recon.universe(api, handle, i01["base_address"],
                                           i01["image_size_bytes"])
        note = []
        verdict = readiness.prove_gameplay(eri, api, handle, objects,
                                           namepool=namepool, note=note)
        if not verdict["ready"]:
            return None

        # Exactly one, or the reading is ambiguous and no number is honest.
        found = verdict["facts"].get("player_inventories") or []
        if len(found) != 1:
            return None
        address = int(found[0]["address"], 16)

        array = address + inv["off_inventory_array"]
        data = eri._read_u64(api, handle, array)
        count = eri._read_u32(api, handle, array + 8)
        if not data or count <= 0 or count > 4096:
            return None
        # The inventory's OWN item counter, for corroboration. Its exact
        # semantics are unmeasured -- whether it counts stacks, cells or items
        # is not something this project has established -- so it is recorded
        # rather than asserted on.
        report_count = eri._read_u32(api, handle, address + 192)
        counts = {}
        # Not guessed: CR-01C5's JobRemoveItem already encodes this layout and
        # is exercised in the live game -- an 80-byte slot, an occupied flag in
        # its first BYTE, and the InvItem at +24 whose first field is the item's
        # FName.
        for index in range(count):
            slot = data + index * 80
            if eri._read_u8(api, handle, slot) != 1:
                continue
            entry_id = eri._read_u32(api, handle,
                                     slot + inv["off_invitem_in_slot"])
            try:
                row = eri.decode_fname_entry_id(api, handle, namepool, entry_id)
            except Exception:                                      # noqa: BLE001
                row = None
            if isinstance(row, dict):
                row = row.get("name_text") or row.get("text")
            row = row or ("entry:%d" % entry_id)
            counts[row] = counts.get(row, 0) + 1

        # AN EMPTY PACK IS NOT A READING.
        #
        # The docstring above promises that "empty" and "could not be read" stay
        # distinct, and returning {} here broke that promise everywhere it
        # mattered: every consumer tests `is not None`, and the settle rule
        # compares {} to {} and declares the inventory stable. Two reads taken
        # before the save had restored anything would therefore have settled
        # immediately, on both sides, and the differential would have compared
        # two inventories containing none of the save's own rows -- and passed.
        #
        # From outside the process an all-empty pack cannot be told apart from
        # one the game has not filled yet, so the honest answer is that no
        # reading was obtained.
        if not counts:
            return None
        return counts
    finally:
        try:
            api.close_handle(handle)
        except Exception:                                          # noqa: BLE001
            pass


def read_log(install_root):
    path = sb.fc.framework_path(install_root, "runtime.log")
    if not os.path.isfile(path):
        return ""
    with open(path, encoding="utf-8", errors="replace") as handle:
        return handle.read()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--install-root", default=installer.DEFAULT_INSTALL)
    ap.add_argument("--out", required=True)
    ap.add_argument("--keep-open", action="store_true")
    ap.add_argument("--no-neighbours", dest="with_neighbours",
                    action="store_false", default=True,
                    help="skip the third pass that installs broken mods beside "
                         "the reference mod")
    ap.add_argument("--fresh-snapshot", action="store_true",
                    help="re-take the save snapshot from what is on disk now "
                         "instead of reusing the recorded one")
    a = ap.parse_args(argv)

    checks = []

    def check(label, ok, detail=""):
        checks.append({"check": label, "pass": bool(ok), "detail": str(detail)})
        print("  [%s] %s%s" % ("PASS" if ok else "FAIL", label,
                               "" if ok else "  -- %s" % detail))
        return bool(ok)

    report = {"stage": 7, "mod_id": MOD_ID}
    os.makedirs(WORK, exist_ok=True)

    def why_blocked(entry_dir):
        """The runner's own reason, which it writes to stdout, not stderr."""
        path = os.path.join(entry_dir, "entry.stdout.txt")
        if not os.path.isfile(path):
            return ""
        with open(path, encoding="utf-8", errors="replace") as handle:
            text = handle.read()
        match = BLOCKED_REASON.search(text)
        return match.group(1) if match else ""

    def drive_into_gameplay(tag):
        """Launch from Steam and reach a live world. Returns (ok, detail).

        Retried once, and once only. This machine synthesises clicks at a live
        game, so it depends on the game window holding focus -- a property this
        instrument does not control, and which has cost runs before. A second
        failure is a real finding rather than bad luck.
        """
        if not sweep.launch_to_menu():
            return False, "the game did not launch from Steam"
        attempts = []
        entry, err = None, ""
        for attempt in range(2):
            entry_dir = os.path.join(WORK, "entry-%s-%d" % (tag, attempt))
            entry = sweep.start_gameplay_entry(entry_dir)
            err = sweep.finish_gameplay_entry(entry, entry_dir)
            attempts.append({"attempt": attempt, "returncode": entry.returncode,
                             "blocked_reason": why_blocked(entry_dir)})
            if entry.returncode == 0:
                break
            print("  save entry did not reach gameplay: %s"
                  % (attempts[-1]["blocked_reason"] or (err or "").strip())[:200])
        report.setdefault("save_entry_attempts", {})[tag] = attempts
        report.setdefault("entered_at", {})[tag] = time.time()
        return (entry.returncode == 0,
                (attempts[-1]["blocked_reason"] or (err or ""))[:220])

    def dwell(label, since):
        """Hold both passes in the world for the same time before reading.

        The vanilla side read its inventory the moment gameplay was provable;
        the modded side first waited for a log line. When that wait was short
        the two sides differed by seconds, and when it was not they differed by
        minutes -- in a survival game whose own harness warns that a parked
        character starves. Any row the game consumed or spawned in the
        difference would have landed in the delta and been charged to the mod.
        """
        waited = max(0.0, DWELL_SECONDS - (time.time() - since))
        if waited > 0:
            print("  holding %s in the world for %.0fs, as the other side is"
                  % (label, waited))
            time.sleep(waited)
        report["dwell_%s" % label] = round(time.time() - since, 1)

    def read_settled(label, tries=14, gap=3.0):
        """Read the player's inventory until it stops changing.

        Gameplay becoming PROVABLE and the save being fully restored into the
        player's inventory are not the same moment, and the gap is seconds wide.
        Reading at the first provable instant gave this instrument three
        different answers for the SAME save on three runs -- 0 rows, 2 rows and
        8 rows -- each a snapshot of a different point in its loading. A
        differential between two moving numbers measures nothing.

        So both sides are read identically: repeatedly, until two consecutive
        readings agree. That is the earliest moment the number is a fact about
        the save rather than about the timing of the read. Every reading is kept
        in the report, so the settling is evidence rather than an assertion.
        """
        history = []
        previous = None
        for _ in range(tries):
            current = read_inventory(inv_binding)
            history.append(None if current is None
                           else dict(sorted(current.items())))
            if current is not None and current == previous:
                report["%s_reads" % label] = history
                return current
            previous = current
            time.sleep(gap)
        report["%s_reads" % label] = history
        report["%s_never_settled" % label] = True
        return previous

    def describe(counts):
        if counts is None:
            return "unreadable (no live player inventory)"
        return "%d distinct row(s), %d item(s): %s" % (
            len(counts), sum(counts.values()),
            ", ".join("%s x%d" % kv for kv in sorted(counts.items())))

    # Resolved from the executable, before anything is installed or removed:
    # the vanilla pass below runs with no framework on disk to read it from.
    inv_binding = sb.real_profile(a.install_root)["inventory"]

    # THE INPUT STATE, PINNED.
    #
    # Taken once, restored before each pass, and hashed both times. Until this
    # existed the two sides shared only a menu row, and any change to the save
    # between them -- a manual session, an autosave -- would have been measured
    # as though the mod had caused it.
    sb.fc.close_game()
    if not os.path.isdir(BACKUP_DIR):
        # Written once and never again: whatever was on this machine before the
        # instrument first ran is recoverable, independently of the snapshot
        # that gets restored over and over.
        copy_saves(BACKUP_DIR)
    if a.fresh_snapshot or not os.path.isdir(SNAPSHOT_DIR):
        if os.path.isdir(SNAPSHOT_DIR):
            shutil.rmtree(SNAPSHOT_DIR)
        copy_saves(SNAPSHOT_DIR)
    report["save_snapshot"] = sorted(os.listdir(SNAPSHOT_DIR))
    print("=== the input save state ===")
    print("  snapshot: %s" % ", ".join(report["save_snapshot"]))

    def restore_and_hash(label):
        restored = restore_saves(SNAPSHOT_DIR)
        digests = hash_saves()
        report["save_hashes_%s" % label] = digests
        print("  %s starts from: %s" % (label, ", ".join(
            "%s %s" % (n, h[:12]) for n, h in sorted(digests.items()))))
        return restored, digests


    # THE BASELINE: the same save, entered with the mod NOT installed.
    #
    # A before/after taken inside ONE session cannot answer this, and the first
    # version of this instrument tried. The mod grants on misery:content_ready,
    # which fires the moment the world is published; the save-entry machine
    # reports gameplay from that same condition. So the "before" read begins
    # AFTER the grant has already happened -- it lost that race by about twenty
    # milliseconds -- and would report "nothing changed" however well the grant
    # worked. No change to the framework could fix that: it is the wrong
    # experiment.
    #
    # The differential is therefore across configurations rather than across
    # time: the same save and the same entry machine, without the mod and then
    # with it. That comparison is sound, and it doubles as the vanilla baseline
    # the acceptance needs anyway.
    # CRITERION 10, first half: what the installation looks like untouched.
    # Taken after uninstall so a previous run cannot be part of the baseline.
    # The game's OWN Win64 directory, not the framework's subdirectory of it:
    # the bootstrap proxy is installed directly beside the executable, and a
    # manifest that missed it would call the installation clean while a DLL of
    # ours sat next to MISERY-Win64-Shipping.exe.
    binaries = installer.binaries_dir(a.install_root)
    report["binaries_dir"] = binaries

    print()
    print("=== the same save, entered WITHOUT the mod ===")
    sb.fc.close_game()
    installer.uninstall(a.install_root)
    restore_and_hash("vanilla")
    vanilla_tree = tree_manifest(binaries)
    report["binaries_files_vanilla"] = len(vanilla_tree)
    print("  the installation, uninstalled: %d file(s) under %s"
          % (len(vanilla_tree), os.path.basename(binaries)))
    ok, detail = drive_into_gameplay("vanilla")
    entered_at = report["entered_at"]["vanilla"]
    if not check("the save could be entered with no framework installed",
                 ok, detail):
        return finish(report, checks, a.out)
    dwell("vanilla", entered_at)
    baseline = read_settled("vanilla")
    report["inventory_vanilla"] = baseline
    print("  %s" % describe(baseline))
    if not check("the vanilla player inventory could be read",
                 baseline is not None, "no live player inventory"):
        return finish(report, checks, a.out)
    if not check("the vanilla inventory settled before it was read",
                 not report.get("vanilla_never_settled"),
                 "%d reading(s), still changing"
                 % len(report.get("vanilla_reads") or [])):
        return finish(report, checks, a.out)
    check("the mod's row is absent from the vanilla inventory",
          EXPECTED_ROW not in baseline, sorted(baseline))
    # Whether the GAME rewrote the save during the pass. If it did, the modded
    # side would otherwise inherit it, and the restore below is what prevents
    # that -- but it is worth knowing, and worth recording, either way.
    report["save_hashes_vanilla_after"] = hash_saves()
    check("the game did not rewrite the save during the vanilla pass",
          report["save_hashes_vanilla_after"] == report["save_hashes_vanilla"],
          "changed: %s" % sorted(
              n for n, h in report["save_hashes_vanilla_after"].items()
              if report["save_hashes_vanilla"].get(n) != h))
    sb.fc.close_game()

    print()
    print("=== building and installing ===")
    build_managed()
    report["installed"] = install_everything(a.install_root)
    log_path = sb.fc.framework_path(a.install_root, "runtime.log")
    if os.path.isfile(log_path):
        os.remove(log_path)
    print("  %d file(s) installed" % len(report["installed"]))

    print()
    print("=== what the mod actually ships ===")
    spec = mod_spec()
    parent_path = declared_parent()
    parent_package = parent_path.rsplit(".", 1)[0]
    parent_class = parent_path.rsplit(".", 1)[1]
    report["declared_parent"] = parent_path

    import container_report as cr                                  # noqa: PLC0415
    utoc = sb.fc.framework_path(
        a.install_root,
        os.path.join("Mods", "ReferenceMod", "Content", CONTAINER + ".utoc"))
    shipped = sorted((cr.read_container(utoc).get("package_paths") or []))
    report["container_packages"] = shipped
    print("  %d package(s): %s" % (len(shipped), ", ".join(shipped)))

    # Criterion 3. The surrogate is an authoring-time stand-in that occupies the
    # REAL game object's path so the cooker can resolve a parent it cannot see.
    # Shipping it would put a fake at the address of the game's own class.
    check("the surrogate parent is not in the shipped container",
          parent_package not in shipped, parent_package)
    check("the mod's own blueprint is in the shipped container",
          any(p.endswith("BP_%s" % spec["blueprints"][0]["name"])
              for p in shipped), shipped)

    # Criterion 6. What the mod's assembly needs in order to run.
    named = framework_names_in(
        sb.fc.framework_path(a.install_root,
                             os.path.join("Mods", "ReferenceMod", "Code",
                                          ASSEMBLY)))
    report["framework_names_in_assembly"] = named
    # Namespaces under Misery.ModAPI are the public API too; what must not
    # appear is any OTHER framework assembly.
    foreign = [n for n in named if not n.startswith("Misery.ModAPI")]
    check("no framework assembly other than Misery.ModAPI is named in the "
          "mod's assembly", foreign == [], named)

    print()
    print("=== the same save, entered WITH the mod ===")
    sb.fc.close_game()
    restore_and_hash("modded")
    if not check("both passes start from byte-identical save files",
                 report["save_hashes_modded"] == report["save_hashes_vanilla"],
                 "vanilla=%s modded=%s" % (report["save_hashes_vanilla"],
                                           report["save_hashes_modded"])):
        return finish(report, checks, a.out)
    ok, detail = drive_into_gameplay("modded")
    entered_at = report["entered_at"]["modded"]
    if not check("the save-entry machine reached gameplay", ok, detail):
        # Everything after this reads a world that was never entered, and a
        # cascade of failures caused by one blocked click reads like a broken
        # framework. Stop and say what actually happened.
        return finish(report, checks, a.out)

    print("\n=== waiting for the mod to reach a world ===")
    # BOTH wordings, because the framework has two.
    #
    # ApplyLocked says "is live in generation N; ... resolved it" when the
    # game's lookup succeeds in the same tick as the write. Its own comment
    # records that the usual case is the other branch -- a composite table need
    # not rebuild within that tick -- and VerifyLocked confirms the row on a
    # later poll with different words: "in generation N: ... resolved it
    # (attempt K)". Matching only the first turned the framework's documented
    # slow path into a FAIL on a working run, and left the wait loop below
    # spinning its full 450 seconds while the player stood in a live world.
    live = re.compile(r"items: '(\S+)' (?:is live in generation (\d+); "
                      r"|in generation (\d+): )"
                      r"the game's own SGK ItemDetails resolved it")
    log = ""
    for _ in range(90):
        log = read_log(a.install_root)
        if live.search(log):
            break
        time.sleep(5)
    report["runtime_log"] = log

    print("\n=== what happened ===")
    planned = re.search(r"managed: (\d+) mod\(s\) to load: (.+)", log)
    report["planned"] = planned.group(2).split() if planned else []
    check("the production plan admitted the mod on its manifest alone",
          report["planned"] == [MOD_ID], report["planned"])

    loaded = re.search(r"planned mod\(s\) loaded, \d+ failed: (.+)", log)
    report["loaded"] = loaded.group(1).split() if loaded else []
    check("the mod loaded", report["loaded"] == [MOD_ID], report["loaded"])

    resolved = live.search(log)
    report["row"] = resolved.group(1) if resolved else None
    check("the item registered and the game's own SGK ItemDetails resolved it",
          bool(resolved) and resolved.group(1) == EXPECTED_ROW,
          report["row"])

    granted = re.search(r"items: '(\S+)' -- (\d+) of (\d+) added to the "
                        r"player's inventory", log)
    report["granted"] = granted.groups() if granted else None
    check("the framework reports the grant",
          bool(granted) and int(granted.group(2)) >= 1, report["granted"])

    # THE DIFFERENTIAL: what the game holds, not what the API said it did.
    #
    # This is the check the API's own return value cannot substitute for -- and
    # the check that has to be RIGHT. In the run that produced this revision the
    # framework reported "1 of 1 added" and it was true, but the reading meant
    # to confirm it was looking at 1683 crates instead of at the player.
    dwell("modded", entered_at)
    modded = read_settled("modded")
    report["inventory_modded"] = modded
    print("  %s" % describe(modded))
    if check("the modded player inventory could be read", modded is not None,
             "no live player inventory"):
        check("the modded inventory settled before it was read",
              not report.get("modded_never_settled"),
              "%d reading(s), still changing"
              % len(report.get("modded_reads") or []))
        delta = {row: modded.get(row, 0) - baseline.get(row, 0)
                 for row in set(baseline) | set(modded)}
        delta = {row: n for row, n in delta.items() if n != 0}
        report["inventory_delta"] = delta
        print("  delta vs vanilla: %s" % (delta or "nothing changed"))
        check("the player's inventory differs from vanilla by exactly the "
              "granted row", delta == {EXPECTED_ROW: 1},
              "expected {%r: 1}, got %s" % (EXPECTED_ROW, delta))

    # CRITERION 8, MEASURED FROM OUTSIDE.
    #
    # The runtime already refuses a world class that does not walk to the game's
    # own -- LoadWorldClass returns 45 -- so a successful registration is itself
    # the check. This asks the same question without the framework in the loop,
    # by pointer identity: the child's SuperStruct must BE the game's class
    # object, not a class with a matching name.
    print()
    print("=== the mod's class, and what it really inherits ===")
    try:
        import cr01c3_recon as recon                               # noqa: PLC0415
        api = eri.Win32Api()
        i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
        handle = eri.open_process_read_only(api, i01["pid"])
        try:
            _pool, objects = recon.universe(api, handle, i01["base_address"],
                                            i01["image_size_bytes"])
            child_name = "BP_%s_C" % spec["blueprints"][0]["name"]
            kids = class_objects_named(objects, child_name)
            parents = class_objects_named(objects, parent_class)
            report["child_class"] = [hex(k) for k in kids]
            report["parent_class"] = [hex(p) for p in parents]
            if check("exactly one %s and one %s are live"
                     % (child_name, parent_class),
                     len(kids) == 1 and len(parents) == 1,
                     "child=%s parent=%s" % (report["child_class"],
                                             report["parent_class"])):
                super_ptr = eri._read_u64(api, handle, kids[0] + 0x40)
                report["child_super"] = hex(super_ptr)
                print("  %s @%#x  ->  SuperStruct %#x  (%s @%#x)"
                      % (child_name, kids[0], super_ptr, parent_class,
                         parents[0]))
                check("the mod's class inherits the game's class by pointer "
                      "identity", super_ptr == parents[0],
                      "super=%#x parent=%#x" % (super_ptr, parents[0]))
        finally:
            api.close_handle(handle)
    except Exception as failure:                                   # noqa: BLE001
        check("the mod's class could be inspected", False, repr(failure))

    report["save_hashes_modded_after"] = hash_saves()
    check("the game did not rewrite the save during the modded pass",
          report["save_hashes_modded_after"] == report["save_hashes_modded"],
          "changed: %s" % sorted(
              n for n, h in report["save_hashes_modded_after"].items()
              if report["save_hashes_modded"].get(n) != h))

    # ---------------------------------------------------------------- 11 ----
    if a.with_neighbours:
        print()
        print("=== the same save again, with broken mods installed beside it ===")
        sb.fc.close_game()
        report["neighbours"] = install_neighbours(a.install_root)
        print("  installed beside it: %s" % ", ".join(report["neighbours"]))
        log_path = sb.fc.framework_path(a.install_root, "runtime.log")
        if os.path.isfile(log_path):
            os.remove(log_path)
        restore_and_hash("neighbours")
        if check("the third pass starts from the same save files too",
                 report["save_hashes_neighbours"] == report["save_hashes_vanilla"],
                 "differs"):
            ok, detail = drive_into_gameplay("neighbours")
            entered_at = report["entered_at"]["neighbours"]
            if check("the save-entry machine reached gameplay with neighbours",
                     ok, detail):
                live = re.compile(r"items: '(\S+)' is live in generation (\d+)")
                log = ""
                for _ in range(90):
                    log = read_log(a.install_root)
                    if live.search(log):
                        break
                    time.sleep(5)
                report["runtime_log_neighbours"] = log

                planned = re.search(r"managed: (\d+) mod\(s\) to load: (.+)", log)
                names = sorted(planned.group(2).split()) if planned else []
                report["planned_neighbours"] = names
                check("the plan admits every mod, broken ones included",
                      names == sorted([MOD_ID] + list(report["neighbours"])),
                      names)

                loaded = re.search(r"planned mod\(s\) loaded, (\d+) failed: (.+)",
                                   log)
                report["loaded_neighbours"] = loaded.group(2).split() if loaded else []
                check("the reference mod still loaded",
                      MOD_ID in report["loaded_neighbours"],
                      report["loaded_neighbours"])
                # The broken load-time mod must be REPORTED as failed, not
                # quietly dropped: a mod that vanishes without a word is
                # indistinguishable from one that was never there.
                check("the mod that throws on load is reported as failed",
                      bool(loaded) and int(loaded.group(1)) >= 1,
                      loaded.group(1) if loaded else None)

                # The readiness event must have reached more than one mod, and
                # one of those declared no items at all -- which is the whole
                # point of it not being keyed to the items subsystem.
                subs = re.search(r"misery:content_ready -> (\d+) subscriber\(s\)",
                                 log)
                report["content_ready_subscribers"] = (
                    int(subs.group(1)) if subs else None)
                check("the readiness event reached a mod that declared no items",
                      bool(subs) and int(subs.group(1)) >= 2,
                      report["content_ready_subscribers"])

                granted = re.search(r"items: '(\S+)' -- (\d+) of (\d+) added to "
                                    r"the player's inventory", log)
                report["granted_neighbours"] = granted.groups() if granted else None
                # And it must have been notified DESPITE an earlier subscriber
                # throwing from its handler.
                check("the reference mod was still notified and still granted",
                      bool(granted) and granted.group(1) == EXPECTED_ROW,
                      report["granted_neighbours"])

                dwell("neighbours", entered_at)
                with_neighbours = read_settled("neighbours")
                report["inventory_neighbours"] = with_neighbours
                print("  %s" % describe(with_neighbours))
                if with_neighbours is not None:
                    delta = {row: with_neighbours.get(row, 0) - baseline.get(row, 0)
                             for row in set(baseline) | set(with_neighbours)}
                    delta = {row: n for row, n in delta.items() if n != 0}
                    report["inventory_delta_neighbours"] = delta
                    print("  delta vs vanilla: %s" % (delta or "nothing changed"))
                    check("a broken mod beside it changed nothing",
                          delta == {EXPECTED_ROW: 1},
                          "expected {%r: 1}, got %s" % (EXPECTED_ROW, delta))

    # ---------------------------------------------------------------- 10 ----
    print()
    print("=== after uninstall ===")
    sb.fc.close_game()
    report["uninstalled"] = installer.uninstall(a.install_root)
    after_tree = tree_manifest(binaries)
    report["binaries_files_after"] = len(after_tree)
    added = sorted(set(after_tree) - set(vanilla_tree))
    removed = sorted(set(vanilla_tree) - set(after_tree))
    changed = sorted(p for p in set(after_tree) & set(vanilla_tree)
                     if after_tree[p] != vanilla_tree[p])
    report["tree_added"] = added
    report["tree_removed"] = removed
    report["tree_changed"] = changed
    print("  %d file(s); added=%d removed=%d changed=%d"
          % (len(after_tree), len(added), len(removed), len(changed)))
    check("uninstall leaves nothing of the framework behind", added == [], added)
    check("uninstall removes nothing that was the game's", removed == [], removed)
    check("uninstall changes no file of the game's", changed == [], changed)

    if not a.keep_open:
        sb.fc.close_game()
    return finish(report, checks, a.out)


def finish(report, checks, path):
    report["checks"] = checks
    report["passed"] = sum(1 for c in checks if c["pass"])
    report["failed"] = sum(1 for c in checks if not c["pass"])
    report["verdict"] = "PASS" if report["failed"] == 0 else "FAIL"
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=2, default=str)
        handle.write("\n")
    print("\n%s -- %d passed, %d failed -> %s"
          % (report["verdict"], report["passed"], report["failed"], path))
    return 0 if report["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
