#!/usr/bin/env python3
"""Read a built ``.utoc`` and say what is actually inside it.

Why this exists as its own step
-------------------------------
UnrealPak's exit code does not describe its output. A container built with the
wrong ``-CookedDirectory`` resolved none of its packages, reported every miss as
a *warning*, exited **0**, and produced a 48-byte -- i.e. empty -- ``.ucas``.
Nothing downstream of an exit-code check would have noticed until the game asked
for an asset that was never shipped.

So the container is opened and read back, and the build is graded on its contents:

``chunk_types``
    A histogram over ``FIoChunkId.ChunkType``. Types 8 and 9 (ShaderCodeLibrary,
    ShaderCode) are the ones that matter: a shader library's chunk id is
    ``CityHash64(lower(LibraryName-Format))``, so a library named as the game's
    produces the SAME id, and ``FFileIoStore::Resolve`` answers from whichever
    mounted container it reaches first. A mod container carrying those chunks
    could silently answer for the game's own shaders.

``package_paths``
    Recovered from the directory index, so the check is against what the file
    says it holds rather than against what the build intended to put there.

Read-only: this opens containers we built, and never writes to any of them.
"""
import argparse
import collections
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from fingerprint import container_info as ci                        # noqa: E402

# ``../../../MISERY/Content`` is where a mounted container places the content
# root, so this prefix maps a stored file path back to a /Game package path.
CONTENT_MOUNT = "../../../MISERY/Content/"
PACKAGE_EXTENSIONS = (".uasset", ".umap")
NONE_INDEX = 0xFFFFFFFF


class ContainerReadError(Exception):
    pass


def _u32(raw, offset):
    return struct.unpack_from("<I", raw, offset)[0]


def _fstring(raw, offset):
    """UE FString: int32 length; negative means UTF-16. Returns (text, next)."""
    (length,) = struct.unpack_from("<i", raw, offset)
    offset += 4
    if length == 0:
        return "", offset
    if length > 0:
        data = raw[offset:offset + length]
        return data.split(b"\x00", 1)[0].decode("utf-8", "replace"), offset + length
    count = -length
    data = raw[offset:offset + count * 2]
    return (data.decode("utf-16-le", "replace").split("\x00", 1)[0],
            offset + count * 2)


def parse_directory_index(raw):
    """Rebuild the stored file paths from FIoDirectoryIndexResource.

    The index is a tree: directory entries carry a name and links to their first
    child, next sibling and first file; file entries carry a name and a link to
    the next file in the same directory. Names index a string table. Walking it
    is the only way to recover a path, because no entry stores its own full path.
    """
    mount_point, offset = _fstring(raw, 0)
    directories = []
    count = _u32(raw, offset)
    offset += 4
    for _ in range(count):
        directories.append(struct.unpack_from("<IIII", raw, offset))
        offset += 16
    files = []
    count = _u32(raw, offset)
    offset += 4
    for _ in range(count):
        files.append(struct.unpack_from("<III", raw, offset))
        offset += 12
    strings = []
    count = _u32(raw, offset)
    offset += 4
    for _ in range(count):
        text, offset = _fstring(raw, offset)
        strings.append(text)

    def name_of(index):
        return strings[index] if index != NONE_INDEX and index < len(strings) else ""

    out = []

    def walk(dir_index, prefix):
        while dir_index != NONE_INDEX and dir_index < len(directories):
            name, first_child, next_sibling, first_file = directories[dir_index]
            here = prefix if name == NONE_INDEX else (prefix + name_of(name) + "/")
            file_index = first_file
            while file_index != NONE_INDEX and file_index < len(files):
                file_name, next_file, user_data = files[file_index]
                out.append({"path": here + name_of(file_name), "user_data": user_data})
                file_index = next_file
            walk(first_child, here)
            dir_index = next_sibling

    if directories:
        walk(0, "")
    return {"mount_point": mount_point, "files": out,
            "directory_count": len(directories), "file_count": len(files),
            "string_count": len(strings)}


def package_path_for(mount_point, stored):
    """A stored container path -> the /Game package path, or None."""
    full = ((mount_point or "") + stored).replace("\\", "/")
    root, extension = os.path.splitext(full)
    if extension.lower() not in PACKAGE_EXTENSIONS:
        return None
    index = full.find(CONTENT_MOUNT)
    if index < 0:
        return None
    return "/Game/" + root[index + len(CONTENT_MOUNT):]


def read_container(utoc_path):
    """Header, chunk-type histogram and package list for one container."""
    if not os.path.isfile(utoc_path):
        raise ContainerReadError("no container at %r" % utoc_path)
    warnings = []
    decoded, _literals, _annotation = ci.parse_utoc(
        utoc_path, os.path.basename(utoc_path), warnings)
    with open(utoc_path, "rb") as handle:
        raw = handle.read()
    header = ci.decode_toc_header_fields(raw[:ci.TOC_HEADER_SIZE_EXPECTED])
    if header["toc_header_size"] != ci.TOC_HEADER_SIZE_EXPECTED:
        raise ContainerReadError("%s declares a %d-byte header, not the %d this "
                                 "build is known to use"
                                 % (utoc_path, header["toc_header_size"],
                                    ci.TOC_HEADER_SIZE_EXPECTED))
    version = header["version"]
    layout = ci.toc_body_layout(header, version)
    if layout["signed"]:
        raise ContainerReadError("%s is signed; the directory index offset this tool "
                                 "computes is only valid for unsigned containers"
                                 % utoc_path)
    if layout["total"] != len(raw):
        raise ContainerReadError(
            "%s: the layout implied by the header is %d bytes but the file is %d. "
            "Refusing to report contents from a layout that does not add up."
            % (utoc_path, layout["total"], len(raw)))

    # Chunk types: FIoChunkId is 12 bytes and the type is its LAST byte.
    types = collections.Counter()
    chunk_ids = []
    base = layout["offsets"]["chunk_ids"]
    for index in range(header["toc_entry_count"]):
        blob = raw[base + index * ci.IO_CHUNK_ID_SIZE:
                   base + (index + 1) * ci.IO_CHUNK_ID_SIZE]
        types[blob[11]] += 1
        # The whole 12 bytes, not just the u64: two chunks may share an id and
        # differ only by index or type, and a collision check that dropped those
        # bytes would report a clash that is not one.
        chunk_ids.append(blob.hex())

    index_offset = layout["directory_index_offset"]
    index_size = layout["directory_index_size"]
    directory = {"mount_point": "", "files": []}
    if index_size:
        directory = parse_directory_index(raw[index_offset:index_offset + index_size])

    packages, other_files = [], []
    for entry in directory["files"]:
        package = package_path_for(directory["mount_point"], entry["path"])
        (packages if package else other_files).append(package or entry["path"])

    ucas = os.path.splitext(utoc_path)[0] + ".ucas"
    return {
        "utoc": utoc_path,
        "utoc_bytes": len(raw),
        "ucas_bytes": os.path.getsize(ucas) if os.path.isfile(ucas) else None,
        "toc_version": version,
        "entry_count": header["toc_entry_count"],
        "chunk_types": {int(k): int(v) for k, v in sorted(types.items())},
        "chunk_ids": chunk_ids,
        "container_id": header["container_id"],
        "mount_point": directory["mount_point"],
        "package_paths": sorted(packages),
        "non_package_files": sorted(other_files),
        "warnings": warnings,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="report the contents of a .utoc")
    ap.add_argument("utoc", nargs="+")
    ap.add_argument("--out")
    a = ap.parse_args(argv)
    reports = [read_container(path) for path in a.utoc]
    for report in reports:
        print("%s: %d entries, chunk types %s, %d package(s), mount %r"
              % (os.path.basename(report["utoc"]), report["entry_count"],
                 report["chunk_types"], len(report["package_paths"]),
                 report["mount_point"]))
        for package in report["package_paths"]:
            print("    " + package)
        if report["non_package_files"]:
            print("    non-package files: %s" % report["non_package_files"])
    if a.out:
        with open(a.out, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(reports, handle, indent=2)
            handle.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
