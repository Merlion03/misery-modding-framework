#!/usr/bin/env python3
"""Per-mod settings: declared, typed, validated, and persisted per ModId.

DECLARED, NOT FREE-FORM
-----------------------
A mod declares every setting it has -- name, type, default, description -- and
reading or writing anything else is a structured error rather than a silent
default. That is deliberate and it is the whole value of the subsystem: a
free-form dictionary turns a typo into a setting that reads as "off" forever and
gives the author nothing to debug. It also means the developer console can list
a mod's settings and their meanings without the mod being loaded.

TYPES ARE THE FOUR THAT SURVIVE EVERY BOUNDARY
----------------------------------------------
bool, int, float, string. Not because richer types are worthless, but because
each one has to have an unambiguous representation in JSON on disk, in the C ABI,
and in C#. A list or a nested object has several plausible mappings in at least
one of those, and a setting whose meaning depends on which side read it is worse
than a setting that does not exist. A mod needing structure encodes it in a
string it owns the meaning of.

STORAGE IS PER-MOD AND NAMED BY ModId
-------------------------------------
``<root>/<mod_id>.json``. Never one shared file: one mod's malformed settings
must not cost every other mod theirs, and deleting a mod should be able to take
its settings with it.

A STORED VALUE THAT NO LONGER FITS ITS DECLARATION IS NOT FATAL
---------------------------------------------------------------
A mod that changes a setting's type between versions leaves values on disk that
no longer parse. Refusing to load the mod over that would punish the user for
the author's decision, so the value falls back to the declared default and the
substitution is reported. Silence is the thing to avoid, not the fallback.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import errors as E                                                 # noqa: E402
import modid as _modid                                             # noqa: E402

BOOL, INT, FLOAT, STRING = "bool", "int", "float", "string"
TYPES = (BOOL, INT, FLOAT, STRING)

# The ABI representation of each type. Duplicated in the C header and the C#
# enum; a test compares all three.
TYPE_CODES = {BOOL: 1, INT: 2, FLOAT: 3, STRING: 4}

MAX_KEY = 64
MAX_STRING_VALUE = 4096
KEY_PATTERN = _modid.PATTERN          # same identifier rule, one fewer thing to learn


class Setting(object):
    __slots__ = ("key", "type", "default", "description")

    def __init__(self, key, type_name, default, description):
        self.key = key
        self.type = type_name
        self.default = default
        self.description = description

    def as_dict(self):
        return {"key": self.key, "type": self.type, "default": self.default,
                "description": self.description}


def _coerce(value, type_name):
    """Return the value as *type_name*, or raise TypeError.

    ``bool`` is checked before ``int`` throughout because in Python a bool IS an
    int, and letting True satisfy an int setting would make a schema mean less
    than it says.
    """
    if type_name == BOOL:
        if isinstance(value, bool):
            return value
        raise TypeError("expected bool")
    if type_name == INT:
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError("expected int")
        return value
    if type_name == FLOAT:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise TypeError("expected float")
        return float(value)
    if type_name == STRING:
        if not isinstance(value, str):
            raise TypeError("expected string")
        if len(value) > MAX_STRING_VALUE:
            raise TypeError("string longer than %d" % MAX_STRING_VALUE)
        return value
    raise TypeError("unknown setting type %r" % type_name)


class SettingsStore(object):
    """Every mod's settings. One file per mod, written only when changed."""

    def __init__(self, root, logger=None):
        self.root = root
        self._schemas = {}       # mod_id -> {key: Setting}
        self._values = {}        # mod_id -> {key: value}
        self._dirty = set()
        self._logger = logger
        self.substitutions = []  # stored values that no longer fitted

    def path_for(self, mod_id):
        return os.path.join(self.root, "%s.json" % _modid.check(mod_id))

    # ---- declaration ---------------------------------------------------
    def declare(self, owner, definitions):
        """Declare a mod's settings. *definitions* is an iterable of dicts.

        Owned, so unloading a mod forgets its schema and its in-memory values --
        but NOT its file, because the user's configuration should survive a mod
        being disabled and re-enabled.
        """
        mod_id = owner.mod_id
        if mod_id in self._schemas:
            raise E.PlatformError(E.SUB_SETTINGS, E.E_ALREADY_EXISTS,
                                  "settings for %r are already declared" % mod_id,
                                  mod_id)
        schema = {}
        for index, raw in enumerate(definitions):
            where = "settings[%d]" % index
            if not isinstance(raw, dict):
                raise E.PlatformError(E.SUB_SETTINGS, E.E_INVALID_ARGUMENT,
                                      "%s must be a dict" % where, mod_id)
            unknown = sorted(set(raw) - {"key", "type", "default", "description"})
            if unknown:
                raise E.PlatformError(E.SUB_SETTINGS, E.E_INVALID_ARGUMENT,
                                      "%s has unknown key(s) %s" % (where, unknown),
                                      mod_id)
            key = raw.get("key")
            if (not isinstance(key, str) or len(key) > MAX_KEY
                    or not KEY_PATTERN.match(key)):
                raise E.PlatformError(E.SUB_SETTINGS, E.E_INVALID_ARGUMENT,
                                      "%s key %r must match %s and be at most %d "
                                      "characters"
                                      % (where, key, _modid.PATTERN_TEXT, MAX_KEY),
                                      mod_id)
            if key in schema:
                raise E.PlatformError(E.SUB_SETTINGS, E.E_ALREADY_EXISTS,
                                      "%s declares %r twice" % (where, key), mod_id)
            type_name = raw.get("type")
            if type_name not in TYPES:
                raise E.PlatformError(E.SUB_SETTINGS, E.E_INVALID_ARGUMENT,
                                      "%s type %r is not one of %s"
                                      % (where, type_name, list(TYPES)), mod_id)
            if "default" not in raw:
                raise E.PlatformError(E.SUB_SETTINGS, E.E_INVALID_ARGUMENT,
                                      "%s has no default; a setting with no "
                                      "default has no value before the user sets "
                                      "one" % where, mod_id)
            try:
                default = _coerce(raw["default"], type_name)
            except TypeError as error:
                raise E.PlatformError(E.SUB_SETTINGS, E.E_INVALID_ARGUMENT,
                                      "%s default does not match type %r: %s"
                                      % (where, type_name, error), mod_id) from error
            schema[key] = Setting(key, type_name, default,
                                  raw.get("description") or "")
        self._schemas[mod_id] = schema
        self._values[mod_id] = self._load_values(mod_id, schema)

        def release():
            self._schemas.pop(mod_id, None)
            self._values.pop(mod_id, None)
            self._dirty.discard(mod_id)
        return owner.own("settings_schema", mod_id, release,
                         "%d setting(s)" % len(schema))

    def _load_values(self, mod_id, schema):
        values = {key: setting.default for key, setting in schema.items()}
        path = self.path_for(mod_id)
        if not os.path.isfile(path):
            return values
        try:
            with open(path, encoding="utf-8") as handle:
                stored = json.load(handle)
        except (OSError, ValueError) as error:
            self._report(mod_id, None,
                         "settings file could not be read (%s); defaults are in "
                         "use for every key" % error)
            return values
        if not isinstance(stored, dict):
            self._report(mod_id, None,
                         "settings file is not a JSON object; defaults are in use")
            return values
        for key, value in sorted(stored.items()):
            setting = schema.get(key)
            if setting is None:
                # A key the mod no longer declares. Kept on disk (a downgrade
                # should not lose the user's value) but not exposed.
                continue
            try:
                values[key] = _coerce(value, setting.type)
            except TypeError as error:
                self._report(mod_id, key,
                             "stored value %r does not fit declared type %r (%s); "
                             "the default %r is in use"
                             % (value, setting.type, error, setting.default))
        return values

    def _report(self, mod_id, key, message):
        self.substitutions.append({"mod_id": mod_id, "key": key,
                                   "detail": message})
        if self._logger is not None:
            self._logger.log(3, message, mod_id=mod_id, key=key)  # WARN

    # ---- access ---------------------------------------------------------
    def _schema_for(self, mod_id, key):
        schema = self._schemas.get(mod_id)
        if schema is None:
            raise E.PlatformError(E.SUB_SETTINGS, E.E_NOT_FOUND,
                                  "%r has declared no settings" % mod_id, mod_id)
        setting = schema.get(key)
        if setting is None:
            raise E.PlatformError(
                E.SUB_SETTINGS, E.E_NOT_FOUND,
                "%r is not a declared setting of %r. Undeclared keys are refused "
                "so that a typo cannot read as a default forever."
                % (key, mod_id), mod_id)
        return setting

    def get(self, mod_id, key):
        self._schema_for(mod_id, key)
        return self._values[mod_id][key]

    def set(self, mod_id, key, value):
        setting = self._schema_for(mod_id, key)
        try:
            coerced = _coerce(value, setting.type)
        except TypeError as error:
            raise E.PlatformError(E.SUB_SETTINGS, E.E_INVALID_ARGUMENT,
                                  "%r expects %s: %s" % (key, setting.type, error),
                                  mod_id) from error
        if self._values[mod_id][key] != coerced:
            self._values[mod_id][key] = coerced
            self._dirty.add(mod_id)
        return coerced

    def all_for(self, mod_id):
        schema = self._schemas.get(mod_id) or {}
        values = self._values.get(mod_id) or {}
        return {key: values.get(key, schema[key].default) for key in sorted(schema)}

    def schema_for(self, mod_id):
        schema = self._schemas.get(mod_id) or {}
        return [schema[key].as_dict() for key in sorted(schema)]

    # ---- persistence -----------------------------------------------------
    def save(self, mod_id=None):
        """Write dirty mods' files. Keys sorted, so a diff shows real changes."""
        targets = sorted(self._dirty) if mod_id is None else (
            [mod_id] if mod_id in self._dirty else [])
        written = []
        for target in targets:
            path = self.path_for(target)
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            payload = self.all_for(target)
            # Merge over whatever is already on disk so keys the mod no longer
            # declares survive; a user who downgrades gets their values back.
            if os.path.isfile(path):
                try:
                    with open(path, encoding="utf-8") as handle:
                        existing = json.load(handle)
                    if isinstance(existing, dict):
                        merged = dict(existing)
                        merged.update(payload)
                        payload = merged
                except (OSError, ValueError):
                    pass
            with open(path, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True)
                handle.write("\n")
            written.append(path)
            self._dirty.discard(target)
        return written

    def summary(self):
        return {"mods": {mod_id: {"settings": len(self._schemas[mod_id]),
                                  "dirty": mod_id in self._dirty}
                         for mod_id in sorted(self._schemas)},
                "substitutions": list(self.substitutions)}
