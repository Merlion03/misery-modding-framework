#!/usr/bin/env python3
"""``ItemDefinition`` -- the stable, framework-owned way a mod describes an item.

THIS IS NOT ``S_ItemDetails`` AND MUST NEVER BECOME IT
-----------------------------------------------------
``docs/mod-item-definition-boundary.md`` settles why, and the reasons are forcing
rather than stylistic:

  * ``S_ItemDetails`` is a ``UserDefinedStruct`` game asset, 2264 bytes, nesting
    at least ten further game-asset structs. D-10 forbids carrying those into
    the Mod Kit at all.
  * Its property names carry per-asset GUID suffixes (``Weight_7_794436A2...``),
    so any recreation gets different names and tagged serialisation will not
    match.
  * Its memory layout IS the contract: ``AddRow`` copies with
    ``CopyScriptStruct`` using the DESTINATION table's ``RowStruct``, so a source
    buffer is always reinterpreted with the running build's layout. A mod
    shipping its own layout would be misread -- a corruption-class failure, not
    a clean error.

So a mod authors THIS, and a build-specific materializer is the only component
that ever touches the game struct.

WHAT MAY GO IN HERE
-------------------
Only fields whose write has actually been proven against the live game. That is
a deliberate constraint, not an oversight: a definition field with no proven
materialization is a promise the framework cannot keep, and the honest place to
discover that is here rather than three layers down at a memory write.

Every field below traces to a verified live read-back -- see
``research/evidence/`` and the field table in the Stage-2 survey.

IDENTITY
--------
An item is identified by ``ItemId(mod_id, local_id)``. The two are always kept
apart, because they answer different questions: ``mod_id`` says who is
responsible, ``local_id`` says which of that mod's items this is. The row name
the game sees is derived, never authored -- a mod cannot choose a bare name and
therefore cannot collide with, or shadow, a vanilla row by construction.
"""
import os
import re
import sys

_PLATFORM = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))))),
    "tools", "modplatform")
if _PLATFORM not in sys.path:
    sys.path.insert(0, _PLATFORM)
import modid as _modid                                             # noqa: E402

# --------------------------------------------------------------------------
# Structured errors. Never a bare string, never a silent failure.
# --------------------------------------------------------------------------
ERR_INVALID_MOD_ID = "invalid_mod_id"
ERR_INVALID_LOCAL_ID = "invalid_local_id"
ERR_RESERVED_NAMESPACE = "reserved_namespace"
ERR_MISSING_FIELD = "missing_field"
ERR_FIELD_TYPE = "field_type"
ERR_FIELD_RANGE = "field_range"
ERR_TEXT_TOO_LONG = "text_too_long"
ERR_BAD_ASSET_PATH = "bad_asset_path"
ERR_UNSUPPORTED = "unsupported"

# --------------------------------------------------------------------------
# Namespacing
# --------------------------------------------------------------------------
# The derived row name is "<mod_id>__<local_id>". The double underscore is the
# separator, so neither half may contain one -- otherwise two different ItemIds
# could derive the same row name, which would silently turn a collision into an
# overwrite.
ID_PATTERN = _modid.PATTERN
SEPARATOR = _modid.SEPARATOR

# A mod may not claim these. They are how vanilla and the framework itself are
# recognisable, and a mod that could take them could impersonate either.
RESERVED_MOD_IDS = _modid.RESERVED

MAX_ID_LEN = _modid.MAX_LENGTH
MAX_TEXT_LEN = 127          # the probe's text buffers are 128 UTF-16 units incl. NUL

# The one field whose write is conditional on live semantics: AllowStacking is
# only written when the live FBoolProperty is a FULL BYTE, never a bitfield.
# Recorded here so the definition layer knows the constraint exists even though
# only the materializer can evaluate it.
BOOL_FIELDS_REQUIRING_FULL_BYTE = ("allow_stacking",)


class DefinitionError(Exception):
    """A structured validation failure.

    Carries a machine-readable ``code`` and the ``field`` it concerns, because
    "registration failed" with a prose reason is not something a mod loader can
    act on.
    """

    def __init__(self, code, field, detail):
        super().__init__("%s: %s -- %s" % (code, field, detail))
        self.code = code
        self.field = field
        self.detail = detail

    def as_dict(self):
        return {"code": self.code, "field": self.field, "detail": self.detail}


class ItemId(object):
    """``(mod_id, local_id)`` -- and the row name derived from them.

    The row name is DERIVED. A mod never supplies it, which is what makes
    "never shadow a vanilla id by default" true by construction rather than by
    a check someone might forget: every mod row name contains ``__``, and no
    vanilla row does.
    """

    __slots__ = ("mod_id", "local_id")

    def __init__(self, mod_id, local_id):
        # Both halves are checked by the canonical ModId contract rather than
        # by a copy of the rule kept here. The two copies had already drifted
        # from Stage 3's by the time Stage 4 needed one answer.
        try:
            _modid.check(mod_id)
        except _modid.ModIdError as error:
            code = (ERR_RESERVED_NAMESPACE if error.code == _modid.ERR_RESERVED
                    else ERR_INVALID_MOD_ID)
            raise DefinitionError(code, "mod_id", error.detail) from error
        try:
            _modid.check_local_id(local_id)
        except _modid.ModIdError as error:
            raise DefinitionError(ERR_INVALID_LOCAL_ID, "local_id",
                                  error.detail) from error
        self.mod_id = mod_id
        self.local_id = local_id

    @property
    def row_name(self):
        """The FName the game will see. Derived, never authored."""
        return "%s%s%s" % (self.mod_id, SEPARATOR, self.local_id)

    def __eq__(self, other):
        return (isinstance(other, ItemId) and other.mod_id == self.mod_id
                and other.local_id == self.local_id)

    def __hash__(self):
        return hash((self.mod_id, self.local_id))

    def __repr__(self):
        return "ItemId(%r, %r)" % (self.mod_id, self.local_id)

    def as_dict(self):
        return {"mod_id": self.mod_id, "local_id": self.local_id, "row_name": self.row_name}

    @classmethod
    def parse(cls, row_name):
        """Recover an ItemId from a derived row name, or None if it is not one.

        Returning None for a vanilla name is the point: it is how the registry
        tells "a row we could own" from "a row that is not ours to touch".
        """
        if not isinstance(row_name, str) or SEPARATOR not in row_name:
            return None
        mod_id, _, local_id = row_name.partition(SEPARATOR)
        try:
            return cls(mod_id, local_id)
        except DefinitionError:
            return None


class AssetRef(object):
    """A reference to content the MOD owns, by package and asset name.

    Deliberately not a game object pointer and not an engine soft-object struct:
    the definition layer is build-independent, and resolving this to anything
    live is the materializer's job.
    """

    __slots__ = ("package", "asset")

    def __init__(self, package, asset=None):
        if not isinstance(package, str) or not package.startswith("/"):
            raise DefinitionError(ERR_BAD_ASSET_PATH, "package",
                                  "must be an absolute content path starting with '/'")
        if asset is None:
            asset = package.rsplit("/", 1)[-1]
        if not isinstance(asset, str) or not asset:
            raise DefinitionError(ERR_BAD_ASSET_PATH, "asset", "must be a non-empty string")
        self.package = package
        self.asset = asset

    @property
    def object_path(self):
        return "%s.%s" % (self.package, self.asset)

    def __eq__(self, other):
        return (isinstance(other, AssetRef) and other.package == self.package
                and other.asset == self.asset)

    def __hash__(self):
        return hash((self.package, self.asset))

    def __repr__(self):
        return "AssetRef(%r)" % self.object_path

    def as_dict(self):
        return {"package": self.package, "asset": self.asset,
                "object_path": self.object_path}


# How the drag ("move") icon is chosen when the definition does not give one.
DRAG_ICON_SAME_AS_INVENTORY = "same_as_inventory"
DRAG_ICON_EXPLICIT = "explicit"
DRAG_ICON_POLICIES = (DRAG_ICON_SAME_AS_INVENTORY, DRAG_ICON_EXPLICIT)


class Transform(object):
    """The world placement offset. Rotation is a quaternion.

    Scale defaults to (1,1,1) and is validated as non-zero, because a zeroed
    FTransform means scale (0,0,0) -- an actor that spawns correctly, is
    possessed correctly, and is invisible. That cost a gate once.
    """

    __slots__ = ("translation", "rotation", "scale")

    def __init__(self, translation=(0.0, 0.0, 0.0), rotation=(0.0, 0.0, 0.0, 1.0),
                 scale=(1.0, 1.0, 1.0)):
        for name, value, length in (("translation", translation, 3),
                                    ("rotation", rotation, 4), ("scale", scale, 3)):
            if not isinstance(value, (tuple, list)) or len(value) != length:
                raise DefinitionError(ERR_FIELD_TYPE, name,
                                      "must be a sequence of %d numbers" % length)
            for component in value:
                if not isinstance(component, (int, float)):
                    raise DefinitionError(ERR_FIELD_TYPE, name, "components must be numbers")
        if all(float(c) == 0.0 for c in scale):
            raise DefinitionError(
                ERR_FIELD_RANGE, "scale",
                "scale (0,0,0) spawns an actor that is correct in every way except that "
                "it cannot be seen. A zeroed FTransform is the default, so this is an easy "
                "mistake and is refused rather than shipped")
        self.translation = tuple(float(c) for c in translation)
        self.rotation = tuple(float(c) for c in rotation)
        self.scale = tuple(float(c) for c in scale)

    def as_dict(self):
        return {"translation": list(self.translation), "rotation": list(self.rotation),
                "scale": list(self.scale)}


class ItemDefinition(object):
    """What a mod authors. Validated on construction, never partially valid.

    Construction either yields a definition every field of which has been
    checked, or raises ``DefinitionError`` naming the field and a machine
    readable code. There is no "mostly valid" state for a caller to act on.
    """

    SCHEMA_VERSION = 1

    __slots__ = ("item_id", "display_name", "short_name", "description", "weight",
                 "width", "height", "allow_stacking", "max_stack", "inventory_icon",
                 "drag_icon", "drag_icon_policy", "drag_icon_size", "world_mesh",
                 "world_class", "transform")

    def __init__(self, item_id, display_name, short_name, description, *,
                 weight, width, height, inventory_icon, world_mesh, world_class,
                 allow_stacking=False, max_stack=1, drag_icon=None,
                 drag_icon_policy=DRAG_ICON_SAME_AS_INVENTORY, drag_icon_size=(100, 100),
                 transform=None):
        if not isinstance(item_id, ItemId):
            raise DefinitionError(ERR_FIELD_TYPE, "item_id", "must be an ItemId")
        self.item_id = item_id

        for name, value in (("display_name", display_name), ("short_name", short_name),
                            ("description", description)):
            if not isinstance(value, str) or not value:
                raise DefinitionError(ERR_MISSING_FIELD, name, "must be a non-empty string")
            if len(value) > MAX_TEXT_LEN:
                raise DefinitionError(
                    ERR_TEXT_TOO_LONG, name,
                    "longer than %d characters; the materializer's text buffer is fixed and "
                    "silently truncating a mod's text would be worse than refusing it"
                    % MAX_TEXT_LEN)
        self.display_name = display_name
        self.short_name = short_name
        self.description = description

        if not isinstance(weight, (int, float)) or weight < 0:
            raise DefinitionError(ERR_FIELD_RANGE, "weight", "must be a non-negative number")
        self.weight = float(weight)

        for name, value in (("width", width), ("height", height)):
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise DefinitionError(ERR_FIELD_RANGE, name,
                                      "must be an integer >= 1 (inventory grid cells)")
        self.width, self.height = width, height

        if not isinstance(allow_stacking, bool):
            raise DefinitionError(ERR_FIELD_TYPE, "allow_stacking", "must be a bool")
        if not isinstance(max_stack, int) or isinstance(max_stack, bool) or max_stack < 1:
            raise DefinitionError(ERR_FIELD_RANGE, "max_stack", "must be an integer >= 1")
        if not allow_stacking and max_stack != 1:
            raise DefinitionError(
                ERR_FIELD_RANGE, "max_stack",
                "max_stack %d with allow_stacking False is contradictory; say which you "
                "mean rather than leaving the game to pick" % max_stack)
        self.allow_stacking, self.max_stack = allow_stacking, max_stack

        for name, value in (("inventory_icon", inventory_icon), ("world_mesh", world_mesh)):
            if not isinstance(value, AssetRef):
                raise DefinitionError(ERR_FIELD_TYPE, name, "must be an AssetRef")
        self.inventory_icon, self.world_mesh = inventory_icon, world_mesh

        if drag_icon_policy not in DRAG_ICON_POLICIES:
            raise DefinitionError(ERR_FIELD_TYPE, "drag_icon_policy",
                                  "must be one of %r" % (DRAG_ICON_POLICIES,))
        if drag_icon_policy == DRAG_ICON_EXPLICIT:
            if not isinstance(drag_icon, AssetRef):
                raise DefinitionError(ERR_MISSING_FIELD, "drag_icon",
                                      "policy is 'explicit' but no drag_icon was given")
        elif drag_icon is not None:
            raise DefinitionError(
                ERR_FIELD_TYPE, "drag_icon",
                "a drag_icon was given but the policy is %r; set the policy to 'explicit' "
                "so the intent is stated rather than inferred" % drag_icon_policy)
        self.drag_icon = drag_icon
        self.drag_icon_policy = drag_icon_policy

        if (not isinstance(drag_icon_size, (tuple, list)) or len(drag_icon_size) != 2
                or not all(isinstance(v, int) and not isinstance(v, bool) and v > 0
                           for v in drag_icon_size)):
            raise DefinitionError(ERR_FIELD_TYPE, "drag_icon_size",
                                  "must be two positive integers (x, y)")
        self.drag_icon_size = tuple(int(v) for v in drag_icon_size)

        if not isinstance(world_class, str) or not world_class:
            raise DefinitionError(ERR_MISSING_FIELD, "world_class",
                                  "must name the world actor class")
        self.world_class = world_class

        if transform is None:
            transform = Transform()
        if not isinstance(transform, Transform):
            raise DefinitionError(ERR_FIELD_TYPE, "transform", "must be a Transform")
        self.transform = transform

    # ---- derived -----------------------------------------------------------
    @property
    def row_name(self):
        return self.item_id.row_name

    def effective_drag_icon(self):
        """The icon the drag ghost uses, after the defaulting policy is applied.

        A separate concept from the inventory icon on purpose: a gate was closed
        once by discovering that the drag ghost reads MoveIcon, not
        InventoryIcon, and an item with no MoveIcon drags as nothing at all.
        """
        if self.drag_icon_policy == DRAG_ICON_EXPLICIT:
            return self.drag_icon
        return self.inventory_icon

    def content_refs(self):
        """Every asset this definition needs the runtime to own while registered."""
        refs = [self.inventory_icon, self.world_mesh]
        drag = self.effective_drag_icon()
        if drag not in refs:
            refs.append(drag)
        return refs

    def as_dict(self):
        return {
            "schema_version": self.SCHEMA_VERSION,
            "item_id": self.item_id.as_dict(),
            "display_name": self.display_name, "short_name": self.short_name,
            "description": self.description, "weight": self.weight,
            "width": self.width, "height": self.height,
            "allow_stacking": self.allow_stacking, "max_stack": self.max_stack,
            "inventory_icon": self.inventory_icon.as_dict(),
            "drag_icon_policy": self.drag_icon_policy,
            "drag_icon": self.drag_icon.as_dict() if self.drag_icon else None,
            "effective_drag_icon": self.effective_drag_icon().as_dict(),
            "drag_icon_size": list(self.drag_icon_size),
            "world_mesh": self.world_mesh.as_dict(),
            "world_class": self.world_class,
            "transform": self.transform.as_dict(),
        }

    def __repr__(self):
        return "ItemDefinition(%r)" % self.row_name
