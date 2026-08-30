#!/usr/bin/env python3
"""THE ModId contract. One rule, one place, for every stage that consumes it.

WHY THIS FILE EXISTS
--------------------
Three stages independently decided what a mod may be called, and by Stage 4 they
had drifted:

    Stage 3 (tools/modkit/namespace.py)     accepted "has__separator"
    Stage 2 (research/.../items/definition)  refused it
    Stage 4 (tools/modframework/manifest)    enforced the intersection by hand

Each rule was locally correct. Stage 3 puts the id in a package path, where
``__`` is harmless. Stage 2 derives an item row name as ``<mod_id>__<local_id>``,
where an id containing ``__`` makes the decomposition ambiguous -- ``a__b__c``
could be ``(a, b__c)`` or ``(a__b, c)``. But an id is used by BOTH, so the set a
mod may actually be called from is the intersection, and nobody owned it.

The fix is not a fourth validator. It is one canonical rule that every consumer
delegates to, so a future stage cannot add a fifth opinion without editing this
file and seeing what else depends on it.

WHY THE RULE IS WHAT IT IS
--------------------------
``^[a-z][a-z0-9_]*$``, no ``__``, at most 48 characters, and not reserved.

  lowercase        FName comparison in the engine is case-insensitive, so
                   "AlphaMod" and "alphamod" are ONE name to the game while
                   looking like two in a manifest. Allowing case would let two
                   mods that appear distinct collide inside MISERY.
  starts a-z       An id is used to build identifiers on three sides (a package
                   path, an FName, and a C# property-safe token). Leading digits
                   are illegal in enough of those to be worth refusing outright.
  no "__"          The row-name separator, above.
  <= 48            Row names, package paths and container stems all embed it,
                   and every one of those has its own length limit further down.
  not reserved     A mod that could call itself "misery" or "core" could
                   impersonate the game or the framework.

THIS RULE IS AT LEAST AS STRICT AS EVERY CONSUMER'S OWN RULE. That is the
invariant a test pins: anything accepted here must be accepted by Stage 2 and
Stage 3, so consolidating can never admit something a stage would refuse. Going
the other way -- an id a stage once accepted and this now refuses -- is possible
by construction (``has__separator`` is exactly that), and safe, because such an
id could never have completed a load end to end anyway: Stage 2 would have
refused its very first item.
"""
import re

# The pattern is deliberately duplicated in the C bridge header and in the C#
# ModId type. A test compares all three, because three copies of a rule that
# nobody compares is how the drift this file exists to end got started.
PATTERN_TEXT = r"^[a-z][a-z0-9_]*$"
PATTERN = re.compile(PATTERN_TEXT)

SEPARATOR = "__"
MAX_LENGTH = 48

# Reserved: the game, the engine, and the framework's own names. A mod holding
# one of these could impersonate something the user is entitled to trust.
# EXACTLY the union of the two sets this replaces: Stage 2's and Stage 3's.
# Nothing more.
#
# A first draft added the framework's own vocabulary here -- "framework",
# "runtime", "platform", "mbpl" and so on -- on the reasoning that a mod should
# not be able to impersonate the framework either. That reasoning is fine; doing
# it in the same change as the consolidation was not. "mbpl" is the mod_id the
# PROVEN production radio actually uses, so reserving it broke every Stage 2
# definition and the radio with them.
#
# The consolidation is allowed to be a superset of the old rules and nothing
# else, because that is the only change that cannot reject an id which already
# works. Reserving a new name is a separate decision that has to be taken
# against a survey of the ids in use, and it is not this stage's to take.
RESERVED = frozenset({
    "misery", "sgk", "engine", "core", "game", "vanilla",   # Stage 2 and 3
    "mods", "temp", "script",                               # Stage 3 only
})

# Error codes. Closed set, so a caller can branch on the reason rather than on
# the text of a message.
ERR_NOT_A_STRING = "mod_id_not_a_string"
ERR_EMPTY = "mod_id_empty"
ERR_TOO_LONG = "mod_id_too_long"
ERR_SYNTAX = "mod_id_syntax"
ERR_SEPARATOR = "mod_id_contains_separator"
ERR_RESERVED = "mod_id_reserved"

ALL_ERRORS = frozenset({ERR_NOT_A_STRING, ERR_EMPTY, ERR_TOO_LONG, ERR_SYNTAX,
                        ERR_SEPARATOR, ERR_RESERVED})


class ModIdError(ValueError):
    """A refused id, carrying WHICH rule refused it."""

    def __init__(self, code, mod_id, detail):
        super().__init__("%s: %r -- %s" % (code, mod_id, detail))
        self.code = code
        self.mod_id = mod_id
        self.detail = detail


def check(mod_id):
    """Return *mod_id* if it is a legal ModId; otherwise raise ModIdError.

    Every rule is checked in a fixed order and the FIRST failure is reported, so
    the same bad id always produces the same diagnostic. A validator whose
    message depended on dict ordering would make two runs disagree about why
    they refused the same thing.
    """
    if not isinstance(mod_id, str):
        raise ModIdError(ERR_NOT_A_STRING, mod_id,
                         "must be a string, got %s" % type(mod_id).__name__)
    if not mod_id:
        raise ModIdError(ERR_EMPTY, mod_id, "must not be empty")
    if len(mod_id) > MAX_LENGTH:
        raise ModIdError(ERR_TOO_LONG, mod_id,
                         "is %d characters; the limit is %d because row names, "
                         "package paths and container stems all embed it"
                         % (len(mod_id), MAX_LENGTH))
    if not PATTERN.match(mod_id):
        raise ModIdError(
            ERR_SYNTAX, mod_id,
            "must match %s -- lowercase, starting with a letter. Engine FName "
            "comparison is case-insensitive, so two ids differing only in case "
            "would be one name to the game while looking distinct here"
            % PATTERN_TEXT)
    if SEPARATOR in mod_id:
        raise ModIdError(
            ERR_SEPARATOR, mod_id,
            "contains %r, which separates a mod id from a local item id. An id "
            "containing it makes the row name ambiguous to decompose"
            % SEPARATOR)
    if mod_id in RESERVED:
        raise ModIdError(ERR_RESERVED, mod_id,
                         "is reserved; a mod using it could impersonate the "
                         "game or the framework")
    return mod_id


def is_valid(mod_id):
    try:
        check(mod_id)
    except ModIdError:
        return False
    return True


def check_local_id(local_id):
    """The other half of a row name, held to the same rule.

    Both halves of ``<mod_id>__<local_id>`` become one FName, so both are
    subject to the same constraints -- and a local id containing the separator
    would decompose to a DIFFERENT mod, which is worse than merely invalid.
    Reserved names do not apply here: a local id is already namespaced by the
    mod it belongs to, so "core" as a LOCAL id impersonates nothing.
    """
    if not isinstance(local_id, str):
        raise ModIdError(ERR_NOT_A_STRING, local_id,
                         "must be a string, got %s" % type(local_id).__name__)
    if not local_id:
        raise ModIdError(ERR_EMPTY, local_id, "must not be empty")
    if len(local_id) > MAX_LENGTH:
        raise ModIdError(ERR_TOO_LONG, local_id,
                         "is %d characters; the limit is %d"
                         % (len(local_id), MAX_LENGTH))
    if not PATTERN.match(local_id):
        raise ModIdError(ERR_SYNTAX, local_id,
                         "must match %s" % PATTERN_TEXT)
    if SEPARATOR in local_id:
        raise ModIdError(
            ERR_SEPARATOR, local_id,
            "contains %r; the resulting row name would decompose to a different "
            "mod than the one that declared it" % SEPARATOR)
    return local_id


def row_name(mod_id, local_id):
    """The FName the game will see. Derived, never authored."""
    return "%s%s%s" % (check(mod_id), SEPARATOR, check_local_id(local_id))


def split_row_name(name):
    """``<mod_id>__<local_id>`` -> the pair, or None if it is not one of ours.

    Unambiguous precisely because neither half may contain the separator, so the
    FIRST occurrence is always the real one. This function is the reason that
    rule exists.
    """
    if not isinstance(name, str) or SEPARATOR not in name:
        return None
    mod_id, _, local_id = name.partition(SEPARATOR)
    if not is_valid(mod_id):
        return None
    try:
        check_local_id(local_id)
    except ModIdError:
        return None
    return (mod_id, local_id)
