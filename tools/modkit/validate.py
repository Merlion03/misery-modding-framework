#!/usr/bin/env python3
"""Validation, before anything is built and again after it is packaged.

Two halves, and they answer different questions.

``validate_spec``  -- can this be built at all? Namespaces, duplicate object
                      paths, missing sources, slot-to-material mapping, texture
                      references, unsupported material features. Cheap, offline,
                      and it runs before the editor is ever launched, because a
                      cook takes minutes and a typo should not cost one.

``validate_container`` -- is what came out safe to stage? Every generated object
                      path present, nothing outside this mod's namespace, and
                      above all NO SHADER ARCHIVE CHUNKS. That last one is not
                      hygiene: a shader library named as the game's hashes to the
                      same chunk id, and the IoStore backend answers a chunk from
                      whichever mounted container it finds first. A container
                      that shipped one could silently answer for the game's own
                      shaders.

Every finding carries a code. "Validation failed" with prose is not something a
build script can branch on.
"""
import os

import namespace as ns

# EIoChunkType values that matter here. 8 and 9 are the shader library and the
# shader code itself; either in a mod container means shader generation happened.
CHUNK_EXPORT_BUNDLE = 1
CHUNK_CONTAINER_HEADER = 6
CHUNK_SHADER_CODE_LIBRARY = 8
CHUNK_SHADER_CODE = 9
FORBIDDEN_CHUNK_TYPES = {CHUNK_SHADER_CODE_LIBRARY: "ShaderCodeLibrary",
                         CHUNK_SHADER_CODE: "ShaderCode"}


class Finding(object):
    __slots__ = ("code", "where", "detail", "fatal")

    def __init__(self, code, where, detail, fatal=True):
        self.code, self.where, self.detail, self.fatal = code, where, detail, fatal

    def as_dict(self):
        return {"code": self.code, "where": self.where, "detail": self.detail,
                "fatal": self.fatal}

    def __repr__(self):
        return "%s[%s] %s: %s" % ("FATAL" if self.fatal else "warn", self.code,
                                  self.where, self.detail)


def validate_spec(spec):
    """Everything checkable before the editor runs. Returns a list of Findings."""
    findings = []
    seen_paths = {}

    def claim(path, where):
        """Two declarations deriving one object path is a build that would
        silently overwrite one asset with another."""
        if path in seen_paths:
            findings.append(Finding(
                "duplicate_object_path", where,
                "%r is already produced by %s. Two declarations deriving one path "
                "means one silently overwrites the other." % (path, seen_paths[path])))
        else:
            seen_paths[path] = where

    # ---- namespace -------------------------------------------------------
    try:
        ns.check_mod_id(spec.mod_id)
    except ns.NamespaceError as exc:
        findings.append(Finding(exc.code, "$.mod_id", exc.detail))

    # ---- textures --------------------------------------------------------
    texture_names = set()
    for texture in spec.textures:
        where = "textures[%s]" % texture.name
        if texture.name in texture_names:
            findings.append(Finding("duplicate_name", where,
                                    "two textures are named %r" % texture.name))
        texture_names.add(texture.name)
        claim(spec.texture_path(texture.name), where)
        source = spec.source_of(texture.source)
        if not os.path.isfile(source):
            findings.append(Finding("missing_source", where,
                                    "no such file: %s" % source))

    # ---- materials -------------------------------------------------------
    material_names = set()
    for material in spec.materials:
        where = "materials[%s]" % material.name
        if material.name in material_names:
            findings.append(Finding("duplicate_name", where,
                                    "two materials are named %r" % material.name))
        material_names.add(material.name)
        claim(spec.material_path(material.name), where)
        for diagnostic in material.diagnostics:
            findings.append(Finding("unsupported_material_feature", where,
                                    "%s -- %s" % (diagnostic["feature"],
                                                  diagnostic["reason"])))
        for field, value in (("base_color", material.base_color),
                             ("normal", material.normal)):
            if isinstance(value, dict) and "texture" in value:
                if value["texture"] not in texture_names:
                    findings.append(Finding(
                        "unknown_texture_reference", "%s.%s" % (where, field),
                        "%r is not a declared texture" % value["texture"]))
        for field, value in (("ao", material.ao), ("roughness", material.roughness),
                             ("metallic", material.metallic)):
            if value is not None and not 0.0 <= value <= 1.0:
                findings.append(Finding("field_range", "%s.%s" % (where, field),
                                        "%r is outside 0..1" % value))

    # ---- meshes ----------------------------------------------------------
    mesh_names = set()
    for mesh in spec.meshes:
        where = "meshes[%s]" % mesh.name
        if mesh.name in mesh_names:
            findings.append(Finding("duplicate_name", where,
                                    "two meshes are named %r" % mesh.name))
        mesh_names.add(mesh.name)
        claim(spec.mesh_path(mesh.name), where)
        source = spec.source_of(mesh.source)
        if not os.path.isfile(source):
            findings.append(Finding("missing_source", where,
                                    "no such file: %s" % source))
        for slot in mesh.slots:
            if slot["material"] not in material_names:
                findings.append(Finding(
                    "unknown_material_reference", "%s.slots[%d]" % (where, slot["index"]),
                    "%r is not a declared material" % slot["material"]))

    if not spec.meshes and not spec.textures:
        findings.append(Finding("empty_spec", "$",
                                "nothing to build: no meshes and no textures",
                                fatal=False))
    return findings


def expected_object_paths(spec):
    """Every object path this spec must produce. The build asserts against it."""
    paths = []
    for texture in spec.textures:
        paths.append(ns.object_path(spec.mod_id, "texture", texture.name))
    for material in spec.materials:
        paths.append(ns.object_path(spec.mod_id, "material", material.name))
    for mesh in spec.meshes:
        paths.append(ns.object_path(spec.mod_id, "mesh", mesh.name))
    return sorted(paths)


def validate_container(spec, container_report):
    """Check a packaged container before it is staged.

    *container_report* is the shape ``tools/fingerprint/container_info`` produces
    plus a ``chunk_types`` histogram and a ``package_paths`` list.
    """
    findings = []
    chunk_types = container_report.get("chunk_types") or {}
    for chunk_type, label in FORBIDDEN_CHUNK_TYPES.items():
        count = chunk_types.get(chunk_type) or chunk_types.get(str(chunk_type)) or 0
        if count:
            findings.append(Finding(
                "forbidden_shader_chunk", spec.container_name(),
                "%d chunk(s) of type %d (%s). A shader library named as the game's "
                "hashes to the SAME chunk id, and the IoStore backend answers from "
                "whichever mounted container it reaches first -- so this container "
                "could silently answer for the game's own shaders." % (count, chunk_type,
                                                                      label)))
    if not chunk_types:
        findings.append(Finding("no_chunk_census", spec.container_name(),
                                "the container report carries no chunk histogram, so "
                                "shader safety could not be checked at all"))

    produced = set(container_report.get("package_paths") or [])
    if produced:
        for path in expected_object_paths(spec):
            package = path.rsplit(".", 1)[0]
            if package not in produced:
                findings.append(Finding("missing_generated_asset",
                                        spec.container_name(),
                                        "%r is not in the container" % package))
        stray = [p for p in produced if not ns.is_mod_path(p)]
        if stray:
            findings.append(Finding(
                "content_outside_mod_namespace", spec.container_name(),
                "%d package(s) outside %s: %s. A mod container must ship only its own "
                "content -- referencing game assets is fine, packaging them is not."
                % (len(stray), ns.ROOT, stray[:5])))
        foreign = sorted({ns.owning_mod(p) for p in produced if ns.is_mod_path(p)}
                         - {spec.mod_id})
        if foreign:
            findings.append(Finding(
                "content_from_another_mod", spec.container_name(),
                "packages belonging to %s were found in %s's container"
                % (foreign, spec.mod_id)))
    return findings


def fatal(findings):
    return [f for f in findings if f.fatal]


def summarise(findings):
    return {"total": len(findings), "fatal": len(fatal(findings)),
            "findings": [f.as_dict() for f in findings]}
