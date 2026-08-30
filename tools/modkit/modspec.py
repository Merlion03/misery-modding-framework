#!/usr/bin/env python3
"""The Mod Kit BUILD spec: what a mod author writes to get content built.

THIS IS BUILD-TIME INPUT ONLY. It is not the mod manifest -- discovery, load
order, dependencies and conflicts are Stage 4 and are deliberately absent. A
spec describes what to build, not how a game should find it. The build may emit
metadata a later manifest system can consume; it must not grow into one.

MATERIAL CAPABILITIES ARE CAPABILITIES, NOT ASSUMPTIONS
-------------------------------------------------------
The only route proven safe for the current container backend is a cooked
``MaterialInstanceConstant`` whose parent is a material the GAME already ships,
with texture and scalar overrides and no new shader code. That produces zero
shader permutations and no shader-library chunks, which matters because a
library named the same as the game's hashes to the same chunk id and the mount
order decides who wins.

So each material feature is declared, and each is either

    SUPPORTED    built
    UNSUPPORTED  refused with a named diagnostic, never silently dropped and
                 never silently degraded to something that looks similar

``emissive`` is the live example: it was measured not to be reachable through
the proven parent, so asking for it is an explicit refusal rather than a
surprise at look-at time.
"""
import json
import os

import namespace as ns

# ---------------------------------------------------------------- capabilities
SUPPORTED_MATERIAL_FEATURES = ("base_color", "ao", "roughness", "metallic", "normal")

# Declared so the diagnostic can name the reason, rather than "unknown key".
UNSUPPORTED_MATERIAL_FEATURES = {
    "emissive": ("true emissive is not reachable through the proven vanilla parent. "
                 "Measured: an emissive-overridden instance and an identical control "
                 "were indistinguishable at every angle. A bright base colour can "
                 "approximate a lamp, but that is an approximation and must be authored "
                 "as base_color so it is not mistaken for emission."),
    "custom_shader_graph": ("a custom UMaterial means new shader permutations and a "
                            "shader library. A library named as the game's hashes to "
                            "the same chunk id, and the mount order decides which one "
                            "answers -- so this is not enabled by default."),
    "blend_mode": ("changing blend mode requires a different parent material, and no "
                   "non-opaque parent has been proven for this route."),
    "world_position_offset": ("WPO requires shader code, which this route deliberately "
                              "does not generate."),
    "subsurface": ("no proven parent exposes a subsurface profile through parameter "
                   "overrides alone."),
}

SOURCE_MESH_EXTENSIONS = (".glb", ".gltf", ".fbx")
SOURCE_TEXTURE_EXTENSIONS = (".png", ".tga")

TEXTURE_USAGES = {
    # usage -> (srgb, compression, what it is for)
    "color": (True, "TC_DEFAULT", "base colour / albedo, and inventory icons"),
    "mask": (False, "TC_MASKS", "packed AO / Roughness / Metallic"),
    "normal": (False, "TC_NORMALMAP", "tangent-space normal map"),
}


class SpecError(Exception):
    def __init__(self, code, where, detail):
        super().__init__("%s at %s: %s" % (code, where, detail))
        self.code = code
        self.where = where
        self.detail = detail

    def as_dict(self):
        return {"code": self.code, "where": self.where, "detail": self.detail}


class TextureSpec(object):
    __slots__ = ("name", "source", "usage")

    def __init__(self, mod_id, raw, index):
        where = "textures[%d]" % index
        self.name = _require(raw, "name", str, where)
        ns.check_asset_name(self.name)
        self.source = _require(raw, "source", str, where)
        ext = os.path.splitext(self.source)[1].lower()
        if ext not in SOURCE_TEXTURE_EXTENSIONS:
            raise SpecError("unsupported_source", where,
                            "%r: only %s are exercised by this pipeline"
                            % (ext, ", ".join(SOURCE_TEXTURE_EXTENSIONS)))
        self.usage = raw.get("usage", "color")
        if self.usage not in TEXTURE_USAGES:
            raise SpecError("unknown_usage", where,
                            "%r is not one of %s" % (self.usage, sorted(TEXTURE_USAGES)))

    def as_dict(self):
        return {"name": self.name, "source": self.source, "usage": self.usage}


class MaterialSpec(object):
    """One MaterialInstanceConstant on a game-shipped parent."""

    __slots__ = ("name", "parent", "base_color", "ao", "roughness", "metallic",
                 "normal", "diagnostics")

    def __init__(self, mod_id, raw, index):
        where = "materials[%d]" % index
        self.name = _require(raw, "name", str, where)
        ns.check_asset_name(self.name)
        # The parent is a GAME asset referenced by path. Referencing is not
        # packaging: the container ships no vanilla bytes, and the runtime
        # resolves the import against the real material.
        self.parent = _require(raw, "parent", str, where)
        if not self.parent.startswith("/Game/"):
            raise SpecError("bad_parent", where,
                            "the parent must be a /Game/ material the game already "
                            "ships; %r is not" % self.parent)
        self.diagnostics = []
        for feature, reason in UNSUPPORTED_MATERIAL_FEATURES.items():
            if feature in raw:
                self.diagnostics.append({"feature": feature, "reason": reason,
                                         "where": where})
        self.base_color = raw.get("base_color")
        self.normal = raw.get("normal")
        self.ao = _number(raw, "ao", where, default=1.0)
        self.roughness = _number(raw, "roughness", where, default=0.5)
        self.metallic = _number(raw, "metallic", where, default=0.0)
        if self.base_color is None:
            raise SpecError("missing_field", where,
                            "base_color is required: either {'texture': name} or "
                            "{'constant': [r, g, b]} in linear space")
        _check_colour_source(self.base_color, where + ".base_color")

    def as_dict(self):
        return {"name": self.name, "parent": self.parent,
                "base_color": self.base_color, "normal": self.normal,
                "ao": self.ao, "roughness": self.roughness, "metallic": self.metallic,
                "diagnostics": list(self.diagnostics)}


class MeshSpec(object):
    __slots__ = ("name", "source", "slots", "uniform_scale")

    def __init__(self, mod_id, raw, index):
        where = "meshes[%d]" % index
        self.name = _require(raw, "name", str, where)
        ns.check_asset_name(self.name)
        self.source = _require(raw, "source", str, where)
        ext = os.path.splitext(self.source)[1].lower()
        if ext not in SOURCE_MESH_EXTENSIONS:
            raise SpecError("unsupported_source", where,
                            "%r: only %s are exercised by this pipeline"
                            % (ext, ", ".join(SOURCE_MESH_EXTENSIONS)))
        self.uniform_scale = _number(raw, "uniform_scale", where, default=1.0)
        if self.uniform_scale <= 0:
            raise SpecError("field_range", where, "uniform_scale must be > 0")
        slots = raw.get("slots")
        if not isinstance(slots, list) or not slots:
            raise SpecError("missing_field", where,
                            "slots must be a non-empty list of {'material': name}; a "
                            "mesh with no declared slot would cook with whatever the "
                            "importer happened to assign")
        self.slots = []
        for i, slot in enumerate(slots):
            if not isinstance(slot, dict) or "material" not in slot:
                raise SpecError("field_type", "%s.slots[%d]" % (where, i),
                                "each slot needs a 'material' naming a declared material")
            self.slots.append({"index": i, "material": slot["material"],
                               "slot_name": slot.get("slot_name")})

    def as_dict(self):
        return {"name": self.name, "source": self.source,
                "uniform_scale": self.uniform_scale, "slots": list(self.slots)}


class ModSpec(object):
    """A whole mod's build input, validated on construction."""

    SCHEMA_VERSION = 1
    # Fail closed on an unsupported toolchain rather than producing content whose
    # provenance is ambiguous.
    REQUIRED_UNREAL = "5.4.4"

    __slots__ = ("mod_id", "source_root", "unreal_version", "textures", "materials",
                 "meshes", "diagnostics")

    def __init__(self, raw, source_root):
        self.mod_id = ns.check_mod_id(_require(raw, "mod_id", str, "$"))
        self.source_root = source_root
        self.unreal_version = raw.get("unreal_version", self.REQUIRED_UNREAL)
        if self.unreal_version != self.REQUIRED_UNREAL:
            raise SpecError(
                "unsupported_toolchain", "$",
                "this spec declares Unreal %r but the pipeline is only proven against "
                "%r. Building anyway would produce content whose cook provenance nobody "
                "could state." % (self.unreal_version, self.REQUIRED_UNREAL))
        self.textures = [TextureSpec(self.mod_id, t, i)
                         for i, t in enumerate(raw.get("textures") or [])]
        self.materials = [MaterialSpec(self.mod_id, m, i)
                          for i, m in enumerate(raw.get("materials") or [])]
        self.meshes = [MeshSpec(self.mod_id, m, i)
                       for i, m in enumerate(raw.get("meshes") or [])]
        self.diagnostics = []
        for material in self.materials:
            self.diagnostics.extend(material.diagnostics)

    # ---- derived, deterministic ------------------------------------------
    def texture_path(self, name):
        return ns.package_path(self.mod_id, "texture", name)

    def material_path(self, name):
        return ns.package_path(self.mod_id, "material", name)

    def mesh_path(self, name):
        return ns.package_path(self.mod_id, "mesh", name)

    def container_name(self):
        return ns.container_name(self.mod_id)

    def source_of(self, relative):
        return os.path.normpath(os.path.join(self.source_root, relative))

    def as_dict(self):
        return {"schema_version": self.SCHEMA_VERSION, "mod_id": self.mod_id,
                "unreal_version": self.unreal_version,
                "source_root": self.source_root,
                "container": self.container_name(),
                "textures": [t.as_dict() for t in self.textures],
                "materials": [m.as_dict() for m in self.materials],
                "meshes": [m.as_dict() for m in self.meshes],
                "diagnostics": list(self.diagnostics)}

    @classmethod
    def load(cls, path):
        with open(path, encoding="utf-8") as handle:
            raw = json.load(handle)
        return cls(raw, os.path.dirname(os.path.abspath(path)))


# ------------------------------------------------------------------ helpers
def _require(raw, key, kind, where):
    if not isinstance(raw, dict) or key not in raw:
        raise SpecError("missing_field", where, "%r is required" % key)
    value = raw[key]
    if not isinstance(value, kind):
        raise SpecError("field_type", where,
                        "%r must be %s" % (key, getattr(kind, "__name__", kind)))
    return value


def _number(raw, key, where, default=None):
    if key not in raw:
        return default
    value = raw[key]
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise SpecError("field_type", where, "%r must be a number" % key)
    return float(value)


def _check_colour_source(value, where):
    if not isinstance(value, dict):
        raise SpecError("field_type", where, "must be an object")
    if ("texture" in value) == ("constant" in value):
        raise SpecError("field_type", where,
                        "give exactly one of 'texture' or 'constant'")
    if "constant" in value:
        constant = value["constant"]
        if (not isinstance(constant, (list, tuple)) or len(constant) != 3
                or not all(isinstance(c, (int, float)) and not isinstance(c, bool)
                           for c in constant)):
            raise SpecError("field_type", where,
                            "'constant' must be three linear-space numbers")
