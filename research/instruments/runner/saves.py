#!/usr/bin/env python3
"""Read the save list the load-game menu is about to show -- from disk.

WHY THIS EXISTS. The load-game menu is a list of rows, and clicking "the second
row" is only correct while the ordering holds. It does not hold: MISERY
autosaves, an autosave updates its timestamp, and the list is ordered by
timestamp descending -- so an unattended loop that hardcodes a row index will,
sooner or later, click a different save than the one it was configured with, and
nothing downstream would notice, because "a session loaded" looks identical
either way.

So the row is COMPUTED, not configured. ``%LOCALAPPDATA%\\MISERY\\Saved\\
SaveGames\\SaveGameMetaData.sav`` is an ordinary UE ``GVAS`` save holding an
array of ``S_SaveMetaData`` (slot name, ``DateTime``, level name). Parsing it
gives the same slot names and times the menu renders, and sorting them the way
the menu sorts them gives the row index of a slot BY NAME. The oracle is
``filesystem``: it is a read of a file, not a claim about the game's UI.

The ordering rule (time descending) was checked against the rendered menu, not
assumed -- see ``ROW_ORDER_EVIDENCE`` below. If a future build changes it, the
mismatch shows up as the runner clicking a row whose name it can name, which is
a far better failure than a silent wrong load.

Format transcribed from the UE 5.4 serializer (``GameplayStatics::SaveGameToSlot``
-> ``FMemoryWriter`` + ``UObject::Serialize``); the tagged-property layout is the
standard ``FPropertyTag`` one. Nothing is written; the file is opened read-only.
"""
import datetime
import os
import struct

SAVE_DIR = os.path.expandvars(r"%LOCALAPPDATA%\MISERY\Saved\SaveGames")
METADATA_FILE = "SaveGameMetaData.sav"
GVAS_MAGIC = b"GVAS"

# Checked against the rendered menu on build bace50f7185d, 2026-08-29: the four
# slots displayed top-to-bottom as 123_Auto (29/8 20:07), 123 (29/8 16:25),
# Сохранение 1_Auto (29/8 16:16), Сохранение 1 (1/5 16:19) -- strictly
# descending by Time, and NOT the order they appear in the file.
ROW_ORDER_EVIDENCE = "time-descending, verified against the rendered list 2026-08-29"

# UE ticks are 100ns since 0001-01-01. DateTime's own epoch, not FILETIME's.
TICKS_PER_SECOND = 10_000_000
DATETIME_EPOCH = datetime.datetime(1, 1, 1, tzinfo=datetime.timezone.utc)


class SaveParseError(Exception):
    pass


class _Reader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def take(self, count):
        if self.pos + count > len(self.data):
            raise SaveParseError("read past end of file at %d (+%d)" % (self.pos, count))
        chunk = self.data[self.pos:self.pos + count]
        self.pos += count
        return chunk

    def u8(self):
        return self.take(1)[0]

    def i32(self):
        return struct.unpack("<i", self.take(4))[0]

    def u32(self):
        return struct.unpack("<I", self.take(4))[0]

    def u16(self):
        return struct.unpack("<H", self.take(2))[0]

    def i64(self):
        return struct.unpack("<q", self.take(8))[0]

    def fstring(self):
        """UE FString: positive length = ASCII, negative = UTF-16LE. Both include
        the terminating null, which is stripped here. Zero length is the empty
        string, and is legal."""
        length = self.i32()
        if length == 0:
            return ""
        if length > 0:
            raw = self.take(length)
            return raw[:-1].decode("utf-8", errors="replace")
        raw = self.take(-length * 2)
        return raw[:-2].decode("utf-16-le", errors="replace")


def _skip_header(reader):
    if reader.take(4) != GVAS_MAGIC:
        raise SaveParseError("not a GVAS save")
    reader.i32()                     # SaveGameFileVersion
    reader.i32()                     # PackageFileVersionUE4
    reader.i32()                     # PackageFileVersionUE5
    reader.u16(); reader.u16(); reader.u16()   # engine major/minor/patch
    reader.u32()                     # changelist
    reader.fstring()                 # branch
    reader.i32()                     # custom version format
    for _ in range(reader.i32()):    # custom versions: guid + int32
        reader.take(16)
        reader.i32()
    return reader.fstring()          # SaveGameClassName


KNOWN_PROPERTY_TYPES = frozenset({
    "StrProperty", "IntProperty", "FloatProperty", "BoolProperty", "NameProperty",
    "TextProperty", "StructProperty", "ArrayProperty", "MapProperty", "SetProperty",
    "ObjectProperty", "ByteProperty", "EnumProperty", "DoubleProperty",
    "Int64Property", "UInt32Property", "SoftObjectProperty",
})

# EPropertyTagFlags, PropertyTag.cpp:17-25 (UE 5.4).
TAG_HAS_ARRAY_INDEX = 0x01
TAG_HAS_PROPERTY_GUID = 0x02
TAG_HAS_PROPERTY_EXTENSIONS = 0x04
TAG_HAS_BINARY_OR_NATIVE_SERIALIZE = 0x08
TAG_BOOL_TRUE = 0x10


def read_type_name(reader):
    """FPropertyTypeName: a flat pre-order list of (FName, int32 InnerCount).

    Transcribed from PropertyTypeName.cpp:315-341, whose loading loop is
    literally::

        Remaining = 1
        do { read node; Remaining += Node.InnerCount - 1 } while (Remaining > 0)

    This is UE 5.4's replacement for the old "type is one FName plus a couple of
    special-cased extra FNames" tag layout (PROPERTY_TAG_COMPLETE_TYPE_NAME).
    Reading it as the old format is what makes a 5.4 save look corrupt: the
    stream desyncs at the first Array or Struct property and every subsequent
    length is garbage.

    Returns the node list; ``nodes[0][0]`` is the property's own type.
    """
    nodes = []
    remaining = 1
    while remaining > 0:
        if len(nodes) > 64:
            raise SaveParseError("property type name has more than 64 nodes")
        name = reader.fstring()
        inner = reader.i32()
        nodes.append((name, inner))
        remaining += inner - 1
    return nodes


def _looks_like_property_start(reader, at):
    """Does a tagged-property record begin at *at*? (name FString, then a known type)"""
    probe = _Reader(reader.data)
    probe.pos = at
    try:
        name = probe.fstring()
        if not name or len(name) > 512 or name == "None":
            return False
        return probe.fstring() in KNOWN_PROPERTY_TYPES
    except SaveParseError:
        return False


def find_property_stream(reader, *, max_slack=16):
    """Position *reader* at the first tagged property, and report the slack.

    The header parse above is transcribed from ``FSaveGameHeader::Write``
    (GameplayStatics.cpp:216-236). Rather than trust that arithmetic blindly,
    this VALIDATES that a property record actually begins where it lands and
    reports how many bytes had to be skipped -- normally zero. A silent ``+n``
    correction would hide a format change; a reported slack makes it visible.
    """
    for slack in range(max_slack + 1):
        if _looks_like_property_start(reader, reader.pos + slack):
            reader.pos += slack
            return slack
    raise SaveParseError("no tagged property stream found within %d bytes of offset %d"
                         % (max_slack, reader.pos))


def _read_value(reader, type_nodes, size, flags):
    """One property value, given its already-parsed type name and declared size.

    The declared size is the safety net: whatever this function does or fails to
    do, the caller repositions to ``value_start + size``. A type this parser does
    not decode therefore costs a missing value, never a desynchronised stream.
    """
    root = type_nodes[0][0]
    if root == "BoolProperty":
        return bool(flags & TAG_BOOL_TRUE)      # the value lives in the tag flags
    if root == "StrProperty":
        return reader.fstring()
    if root in ("NameProperty", "SoftObjectProperty"):
        return reader.fstring()
    if root == "IntProperty":
        return reader.i32()
    if root == "Int64Property":
        return reader.i64()
    if root == "FloatProperty":
        return struct.unpack("<f", reader.take(4))[0]
    if root == "DoubleProperty":
        return struct.unpack("<d", reader.take(8))[0]
    if root == "StructProperty":
        struct_name = type_nodes[1][0] if len(type_nodes) > 1 else ""
        if struct_name == "DateTime":
            return reader.i64()
        return _read_properties(reader, stop_at=reader.pos + size)
    if root == "ArrayProperty":
        count = reader.i32()
        inner = type_nodes[1][0] if len(type_nodes) > 1 else ""
        if inner == "StructProperty":
            return [_read_properties(reader) for _ in range(count)]
        return "<unparsed array of %s, %d elements>" % (inner, count)
    return "<undecoded %s>" % root


def _read_properties(reader, stop_at=None):
    """Read a tagged-property list until the ``None`` terminator.

    UE 5.4 FPropertyTag layout, transcribed from PropertyTag.cpp's
    ``operator<<(FStructuredArchive::FSlot, FPropertyTag&)``::

        Name       FName   (an FString here: the save is written through
                            FObjectAndNameAsStringProxyArchive)
        -- stop if Name == "None" --
        TypeName   FPropertyTypeName   (see read_type_name)
        Size       int32
        Flags      uint8   (EPropertyTagFlags)
        [ArrayIndex    int32   if Flags & HasArrayIndex]
        [PropertyGuid  16 bytes if Flags & HasPropertyGuid]
        [extensions             if Flags & HasPropertyExtensions]
        Value      Size bytes

    Every value is bracketed by its declared Size and the reader is repositioned
    to the end of it afterwards, so an undecodable property costs one value, not
    the rest of the file.
    """
    out = {}
    while True:
        if stop_at is not None and reader.pos >= stop_at:
            return out
        name = reader.fstring()
        if name in ("None", ""):
            return out
        type_nodes = read_type_name(reader)
        size = reader.i32()
        flags = reader.u8()
        if flags & TAG_HAS_ARRAY_INDEX:
            reader.i32()
        if flags & TAG_HAS_PROPERTY_GUID:
            reader.take(16)
        if flags & TAG_HAS_PROPERTY_EXTENSIONS:
            raise SaveParseError(
                "property %r carries tag extensions, which this parser does not "
                "decode; refusing to guess at the stream position" % name)
        value_start = reader.pos
        try:
            out[name] = _read_value(reader, type_nodes, size, flags)
        except SaveParseError:
            out[name] = "<unreadable %s>" % type_nodes[0][0]
        reader.pos = value_start + size


def _field(entry, prefix):
    """S_SaveMetaData's fields carry Blueprint's own name mangling
    (``SaveGameSlotNames_11_1DFEE472...``). Matching by prefix is deliberate:
    the GUID suffix changes whenever the struct is re-saved in the editor, so
    matching the full name would break on the next content patch."""
    for key, value in entry.items():
        if key.split("_")[0] == prefix or key.startswith(prefix + "_"):
            return value
    return None


def ticks_to_iso(ticks):
    if not ticks:
        return None
    return (DATETIME_EPOCH + datetime.timedelta(seconds=ticks / TICKS_PER_SECOND)) \
        .strftime("%Y-%m-%dT%H:%M:%SZ")


def read_save_slots(save_dir=None):
    """Every save slot the menu will list, in MENU ORDER (time descending).

    Returns ``[{"row": int, "slot": str, "time": iso, "ticks": int, "level": str}]``.
    """
    save_dir = save_dir or SAVE_DIR
    path = os.path.join(save_dir, METADATA_FILE)
    if not os.path.isfile(path):
        raise SaveParseError("no %s in %s" % (METADATA_FILE, save_dir))
    with open(path, "rb") as f:
        reader = _Reader(f.read())
    _skip_header(reader)
    slack = find_property_stream(reader)
    properties = _read_properties(reader)
    properties["__header_slack_bytes"] = slack
    entries = None
    for key, value in properties.items():
        if key.split("_")[0] == "SaveGameMetaData" and isinstance(value, list):
            entries = value
            break
    if entries is None:
        raise SaveParseError("no SaveGameMetaData array in %s" % path)

    slots = []
    for entry in entries:
        slot = _field(entry, "SaveGameSlotNames")
        ticks = _field(entry, "Time")
        level = _field(entry, "LevelName")
        if not slot:
            continue
        slots.append({"slot": slot, "ticks": ticks or 0,
                      "time": ticks_to_iso(ticks), "level": level})
    slots.sort(key=lambda s: s["ticks"], reverse=True)
    for index, entry in enumerate(slots):
        entry["row"] = index
    return slots


def row_of_slot(slot_name, save_dir=None):
    """The 0-based row index the menu will render *slot_name* at.

    Raises if the slot is absent or ambiguous. Both are hard failures on
    purpose: "the configured save is not in the list" must stop the cycle, not
    fall back to a neighbouring row.
    """
    slots = read_save_slots(save_dir)
    matches = [s for s in slots if s["slot"] == slot_name]
    if not matches:
        raise SaveParseError(
            "configured save %r is not in the save list (%s)"
            % (slot_name, ", ".join(repr(s["slot"]) for s in slots)))
    if len(matches) > 1:
        raise SaveParseError("save name %r is ambiguous: %d slots carry it"
                             % (slot_name, len(matches)))
    return matches[0], slots


def main(argv=None):
    import argparse
    import json
    ap = argparse.ArgumentParser(description="List MISERY save slots in menu order.")
    ap.add_argument("--save-dir", default=None)
    a = ap.parse_args(argv)
    print(json.dumps({"order": ROW_ORDER_EVIDENCE,
                      "slots": read_save_slots(a.save_dir)},
                     indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
