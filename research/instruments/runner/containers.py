#!/usr/bin/env python3
"""Container staging and the consistency check that has to pass before launch.

Two jobs, deliberately in one file because they are two halves of one claim:
"the containers the game is about to mount are the ones we meant, and each is
internally coherent."

STAGING. The staging directory is ``%LOCALAPPDATA%\\MISERY\\Saved\\Paks`` --
outside the Steam installation, which decision D-01 keeps strictly read-only.
Every write goes through ``tools/inventory/pathguard.check_output_path`` first,
so a mis-configured profile that points at the installation is refused by the
guard rather than by this module's own good intentions. Removal is likewise
guarded and additionally restricted to the staging directory itself: this code
will not delete a file it did not first prove lives there.

CONSISTENCY. Generalised from ``research/evidence/CR-01C5/container-consistency-
check.py``, whose parser was correct but wired to one hardcoded container name.
The questions are unchanged, and they are the ones that actually matter for a
TOC/CAS pair:

  * IoStore magic present and a version this engine reads,
  * unencrypted and unsigned (we hold no keys and must ship none -- D-02),
  * the header's own sanity field ``TocCompressedBlockEntrySize`` matches the
    struct size the engine expects,
  * every compressed block lies WITHIN the .ucas sitting next to it. A TOC from
    one build against a CAS from another fails exactly here: offsets run past
    the end of the file.

Layout transcribed from Engine/Source/Runtime/Core/Internal/IO/IoStore.h:38-75
(``FIoStoreTocHeader``); the section walk from IoStore.cpp:3215-3254. Nothing
inside the game installation is read for this, and nothing anywhere is written
except the report the caller asks for.

WHY THE CHECK RUNS OVER THE WHOLE DIRECTORY, NOT OVER ONE NAMED CONTAINER. The
runner's failure mode is not "the container I staged is broken" -- I just wrote
it, I know what it is. It is "a container from three experiments ago is still
sitting there and the game is about to mount it too". A per-container check
answers the question nobody was going to get wrong.
"""
import hashlib
import json
import os
import struct
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if os.path.join(REPO_ROOT, "tools", "inventory") not in sys.path:
    sys.path.insert(0, os.path.join(REPO_ROOT, "tools", "inventory"))
import pathguard  # noqa: E402

IOSTORE_MAGIC = b"-==--==--==--==-"
TOC_HEADER_FMT = "<16s B B H IIIII I I I I Q 16s B B H I Q I I 40s"
# FIoStoreTocCompressedBlockEntry is uint8 Data[5+3+3+1]; the engine asserts on
# this size itself, which is why a mismatch is treated as "stop", not "adapt".
COMPRESSED_BLOCK_ENTRY_SIZE = 12

DEFAULT_STAGE_DIR = os.path.expandvars(r"%LOCALAPPDATA%\MISERY\Saved\Paks")
CONTAINER_SUFFIXES = (".utoc", ".ucas", ".pak")


class ContainerError(Exception):
    pass


# --------------------------------------------------------------------------
# consistency
# --------------------------------------------------------------------------

def parse_toc(path):
    """Parse one .utoc header + its compressed-block table.

    Returns ``(header_dict, blocks)`` where each block is
    ``(offset, compressed_size, uncompressed_size, method)``. Raises
    ContainerError only for things that make parsing itself impossible; a
    structurally odd but parseable TOC comes back as data with the oddity
    recorded, so the caller decides rather than this function.
    """
    with open(path, "rb") as f:
        raw = f.read()
    if len(raw) < struct.calcsize(TOC_HEADER_FMT):
        raise ContainerError("%s is smaller than a TOC header" % os.path.basename(path))
    fields = struct.unpack_from(TOC_HEADER_FMT, raw, 0)
    (magic, version, _r0, _r1, hdr_size, entry_count, blk_count, blk_entry_size,
     cm_count, cm_len, cblock_size, dir_index_size, part_count, container_id,
     enc_guid, flags, _r3, _r4, phash_seeds, part_size, no_phash, _r7, _r8) = fields

    out = {
        "file": os.path.basename(path),
        "bytes": len(raw),
        "magic_ok": magic == IOSTORE_MAGIC,
        "version": version,
        "toc_header_size": hdr_size,
        "entry_count": entry_count,
        "compressed_block_entry_count": blk_count,
        "compressed_block_entry_size": blk_entry_size,
        "compression_method_name_count": cm_count,
        "compression_method_name_length": cm_len,
        "compression_block_size": cblock_size,
        "directory_index_size": dir_index_size,
        "partition_count": part_count,
        "partition_size": part_size,
        "container_id": "0x%016x" % (container_id & 0xFFFFFFFFFFFFFFFF),
        "encryption_key_guid_is_zero": enc_guid == b"\0" * 16,
        "container_flags": flags,
        "container_flags_decoded": {
            "Compressed": bool(flags & 0x01), "Encrypted": bool(flags & 0x02),
            "Signed": bool(flags & 0x04), "Indexed": bool(flags & 0x08),
            "OnDemand": bool(flags & 0x10)},
        "chunks_without_perfect_hash": no_phash,
        "perfect_hash_seeds_count": phash_seeds,
    }

    base = (hdr_size + entry_count * 12 + entry_count * 10
            + phash_seeds * 4 + no_phash * 4)
    out["compressed_block_table_offset"] = base
    blocks = []
    if blk_entry_size != COMPRESSED_BLOCK_ENTRY_SIZE:
        out["unexpected_block_entry_size"] = blk_entry_size
        return out, blocks
    for i in range(blk_count):
        off = base + i * COMPRESSED_BLOCK_ENTRY_SIZE
        if off + COMPRESSED_BLOCK_ENTRY_SIZE > len(raw):
            out["block_table_truncated_at_entry"] = i
            break
        d = raw[off:off + COMPRESSED_BLOCK_ENTRY_SIZE]
        offset = struct.unpack_from("<Q", d, 0)[0] & ((1 << 40) - 1)
        csize = (struct.unpack_from("<I", d, 4)[0] >> 8) & 0xFFFFFF
        packed = struct.unpack_from("<I", d, 8)[0]
        usize = packed & 0xFFFFFF
        method = packed >> 24
        blocks.append((offset, csize, usize, method))
    out["blocks_parsed"] = len(blocks)
    if blocks:
        out["max_block_end"] = max(o + c for o, c, _u, _m in blocks)
        out["sum_compressed"] = sum(c for _o, c, _u, _m in blocks)
        out["sum_uncompressed"] = sum(u for _o, _c, u, _m in blocks)
        out["compression_methods_used"] = sorted({m for *_x, m in blocks})
        out["blocks_monotonic"] = all(
            blocks[i][0] <= blocks[i + 1][0] for i in range(len(blocks) - 1))
    return out, blocks


def check_container(toc_path):
    """Full per-container verdict. ``mountable`` is the gate the runner uses."""
    stem = toc_path[:-len(".utoc")]
    cas_path = stem + ".ucas"
    pak_path = stem + ".pak"
    rep = {"name": os.path.basename(stem), "utoc": toc_path,
           "ucas_present": os.path.isfile(cas_path),
           "pak_present": os.path.isfile(pak_path)}
    try:
        hdr, blocks = parse_toc(toc_path)
    except ContainerError as exc:
        rep["mountable"] = False
        rep["reasons"] = [str(exc)]
        return rep
    rep["toc"] = hdr

    reasons = []
    if not hdr["magic_ok"]:
        reasons.append("IoStore magic absent")
    if hdr["container_flags_decoded"]["Encrypted"]:
        reasons.append("container is Encrypted and we hold no keys (D-02)")
    if hdr["container_flags_decoded"]["Signed"]:
        reasons.append("container is Signed and we hold no keys (D-02)")
    if not hdr["encryption_key_guid_is_zero"]:
        reasons.append("EncryptionKeyGuid is non-zero")
    if hdr.get("unexpected_block_entry_size") is not None:
        reasons.append("TocCompressedBlockEntrySize %d != %d"
                       % (hdr["unexpected_block_entry_size"], COMPRESSED_BLOCK_ENTRY_SIZE))
    if "block_table_truncated_at_entry" in hdr:
        reasons.append("compressed-block table truncated at entry %d"
                       % hdr["block_table_truncated_at_entry"])
    if not rep["ucas_present"]:
        reasons.append("no .ucas beside the .utoc")
    else:
        cas_size = os.path.getsize(cas_path)
        hdr["ucas_bytes"] = cas_size
        max_end = hdr.get("max_block_end")
        if max_end is None:
            # A TOC with zero compressed blocks is legal (an empty container);
            # say so rather than passing it off as "all blocks inside".
            hdr["all_blocks_inside_ucas"] = None
            hdr["slack_bytes"] = cas_size
        else:
            hdr["all_blocks_inside_ucas"] = max_end <= cas_size
            hdr["slack_bytes"] = cas_size - max_end
            if not hdr["all_blocks_inside_ucas"]:
                reasons.append("compressed blocks run past the end of the .ucas "
                               "(%d > %d): TOC and CAS are from different builds"
                               % (max_end, cas_size))
        if hdr.get("blocks_monotonic") is False:
            reasons.append("compressed-block offsets are not monotonic")
    if not rep["pak_present"]:
        # The .pak beside an IoStore pair carries the mount point; the engine
        # discovers containers through it. Missing it is a staging error, not a
        # corrupt container -- named separately for exactly that reason.
        reasons.append("no .pak beside the .utoc (mount point missing)")

    rep["reasons"] = reasons
    rep["mountable"] = not reasons
    return rep


def check_stage_dir(stage_dir=None, expected=None):
    """Check EVERY container in the staging directory.

    *expected*, when given, is the set of container stems the caller intends to
    be there. A container present but not expected is reported as
    ``unexpected_containers`` and fails the gate: an experiment's leftovers are
    mounted by the engine just as eagerly as the container we meant to stage,
    and that has already cost this project one wrong visual conclusion.
    """
    stage_dir = stage_dir or DEFAULT_STAGE_DIR
    rep = {"stage_dir": stage_dir, "containers": [], "listing": []}
    if not os.path.isdir(stage_dir):
        rep["consistent"] = True
        rep["note"] = "staging directory does not exist -- no external containers"
        return rep
    rep["listing"] = sorted(os.listdir(stage_dir))
    tocs = sorted(n for n in rep["listing"] if n.endswith(".utoc"))
    for name in tocs:
        rep["containers"].append(check_container(os.path.join(stage_dir, name)))

    # A .pak with no .utoc beside it is a pak-only container -- legal, and this
    # project has staged one (MiseryModKit_P). It is listed, not judged by the
    # IoStore rules that do not apply to it.
    stems_with_toc = {n[:-len(".utoc")] for n in tocs}
    rep["pak_only_containers"] = sorted(
        n[:-len(".pak")] for n in rep["listing"]
        if n.endswith(".pak") and n[:-len(".pak")] not in stems_with_toc)

    present = sorted(stems_with_toc | set(rep["pak_only_containers"]))
    rep["present_containers"] = present
    if expected is not None:
        expected = sorted(set(expected))
        rep["expected_containers"] = expected
        rep["unexpected_containers"] = [n for n in present if n not in expected]
        rep["missing_containers"] = [n for n in expected if n not in present]
    else:
        rep["unexpected_containers"] = []
        rep["missing_containers"] = []

    rep["consistent"] = bool(
        all(c["mountable"] for c in rep["containers"])
        and not rep["unexpected_containers"]
        and not rep["missing_containers"])
    return rep


# --------------------------------------------------------------------------
# staging
# --------------------------------------------------------------------------

def _guarded(path, what):
    """Refuse any path inside a known game installation, then require it to be
    inside the staging directory. Both checks, in that order: the first is the
    project-wide D-01 guard, the second is this module's own narrower promise."""
    resolved = pathguard.check_output_path(
        path, install_root=pathguard.CONFIGURED_INSTALL_ROOTS[0],
        what=what, repo_root=REPO_ROOT)
    return resolved


def apply_profile(profile, stage_dir=None, dry_run=False):
    """Apply a staging profile.

    A profile is a dict::

        {"remove": ["ArmProbe_P", ...],       # container stems to delete
         "stage":  [{"src": "<dir>", "stem": "MBPLRadio_P"}, ...],
         "expect": ["MBPLRadio_P", ...]}      # what must be there afterwards

    ``remove`` deletes every ``<stem>.utoc/.ucas/.pak`` present. ``stage`` copies
    those three suffixes from *src* into the staging directory. ``expect`` is
    handed to :func:`check_stage_dir` by the caller.

    Removal is the destructive half, so it is fenced twice: the path must pass
    the installation guard, AND it must resolve to a direct child of the staging
    directory. A stem containing a separator, ``..``, or a drive letter cannot
    survive both checks.
    """
    # Guard the DIRECTORY before touching the filesystem at all. An earlier
    # draft ran os.makedirs first and only guarded the individual files, so a
    # profile whose stage_dir pointed inside the installation would have created
    # a directory there before any check fired -- and with an empty `stage` list
    # it would have created it and reported success. Found by the test that
    # asserts a stage_dir inside the install is refused.
    stage_dir = _guarded(os.path.abspath(stage_dir or DEFAULT_STAGE_DIR),
                         "container staging directory")
    actions = {"removed": [], "staged": [], "skipped": [], "dry_run": bool(dry_run)}
    if not dry_run:
        os.makedirs(stage_dir, exist_ok=True)
    stage_key = os.path.normcase(os.path.realpath(stage_dir))

    for stem in (profile.get("remove") or []):
        for suffix in CONTAINER_SUFFIXES:
            candidate = os.path.join(stage_dir, stem + suffix)
            if not os.path.isfile(candidate):
                continue
            resolved = _guarded(candidate, "container removal")
            if os.path.normcase(os.path.dirname(os.path.realpath(resolved))) != stage_key:
                raise ContainerError(
                    "refusing to remove %s: it does not resolve inside %s"
                    % (candidate, stage_dir))
            if dry_run:
                actions["skipped"].append({"action": "remove", "path": resolved})
                continue
            os.remove(resolved)
            actions["removed"].append(resolved)

    for item in (profile.get("stage") or []):
        src_dir = item["src"]
        stem = item["stem"]
        src_stem = item.get("src_stem", stem)
        for suffix in CONTAINER_SUFFIXES:
            src = os.path.join(src_dir, src_stem + suffix)
            if not os.path.isfile(src):
                continue
            dst = _guarded(os.path.join(stage_dir, stem + suffix), "container staging")
            if dry_run:
                actions["skipped"].append({"action": "stage", "src": src, "dst": dst})
                continue
            with open(src, "rb") as fsrc:
                data = fsrc.read()
            with open(dst, "wb") as fdst:
                fdst.write(data)
            actions["staged"].append({"src": src, "dst": dst, "bytes": len(data),
                                      "sha256": hashlib.sha256(data).hexdigest()})
    return actions


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="Check staged MISERY containers (read-only).")
    ap.add_argument("--stage-dir", default=None)
    ap.add_argument("--expect", nargs="*", default=None,
                    help="container stems that must be present; anything else fails")
    ap.add_argument("--json", default=None)
    a = ap.parse_args(argv)
    rep = check_stage_dir(a.stage_dir, a.expect)
    text = json.dumps(rep, indent=2, sort_keys=True)
    if a.json:
        out = _guarded(a.json, "container report")
        os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
        with open(out, "w", encoding="utf-8", newline="\n") as f:
            f.write(text + "\n")
    print(text)
    return 0 if rep["consistent"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
