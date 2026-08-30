#!/usr/bin/env python3
"""The one vocabulary Stage 4 reports problems in.

WHY THE CODES ARE A CLOSED SET
------------------------------
A load plan is only trustworthy if the reason a mod is missing from it can be
stated exactly. Free-text messages cannot be tested, cannot be counted, and
cannot be told apart by a caller deciding whether to show the user "this mod
needs another mod" or "this mod is broken". So every refusal carries a code from
the list below, the list is closed, and a code not in it is a programming error
rather than a new kind of problem.

FATAL MEANS EXCLUDED, NOT "SOMETHING WENT WRONG"
------------------------------------------------
A fatal diagnostic removes its subject from the load plan. That is the whole
meaning of the flag: Stage 4 never reports a problem and loads the mod anyway,
and never loads "the good part" of a mod whose manifest it could not fully
accept. Non-fatal diagnostics exist for things a user should see but which do
not change what loads -- an unused optional dependency, for instance.
"""

# ---- per-manifest, decidable without looking at any other mod --------------
MALFORMED_MANIFEST = "malformed_manifest"
UNSUPPORTED_MANIFEST_VERSION = "unsupported_manifest_version"
INVALID_MOD_ID = "invalid_mod_id"
UNSUPPORTED_FRAMEWORK_API = "unsupported_framework_api"
MISSING_ARTIFACT = "missing_artifact"
CONTENT_NAMESPACE_MISMATCH = "content_namespace_mismatch"

# ---- cross-mod, decidable only over the whole discovered set ---------------
DUPLICATE_MOD_ID = "duplicate_mod_id"
MISSING_DEPENDENCY = "missing_dependency"
INCOMPATIBLE_DEPENDENCY_VERSION = "incompatible_dependency_version"
DEPENDENCY_CYCLE = "dependency_cycle"
EXPLICIT_CONFLICT = "explicit_conflict"
DEPENDENCY_EXCLUDED = "dependency_excluded"

# ---- informational ---------------------------------------------------------
OPTIONAL_DEPENDENCY_ABSENT = "optional_dependency_absent"

ALL_CODES = frozenset({
    MALFORMED_MANIFEST, UNSUPPORTED_MANIFEST_VERSION, INVALID_MOD_ID,
    UNSUPPORTED_FRAMEWORK_API, MISSING_ARTIFACT, CONTENT_NAMESPACE_MISMATCH,
    DUPLICATE_MOD_ID, MISSING_DEPENDENCY, INCOMPATIBLE_DEPENDENCY_VERSION,
    DEPENDENCY_CYCLE, EXPLICIT_CONFLICT, DEPENDENCY_EXCLUDED,
    OPTIONAL_DEPENDENCY_ABSENT,
})

# Every code that, when raised against a mod, keeps it out of the load plan.
FATAL_CODES = ALL_CODES - {OPTIONAL_DEPENDENCY_ABSENT}


class Diagnostic(object):
    """One reason, attributable to one subject.

    *subject* is the mod_id when there is one and the folder path when the
    manifest was too broken to yield an id -- because a mod whose id could not
    be read still has to be reportable, and reporting it as ``None`` would make
    two unreadable manifests indistinguishable.
    """

    __slots__ = ("code", "subject", "detail", "fatal", "related")

    def __init__(self, code, subject, detail, fatal=None, related=()):
        if code not in ALL_CODES:
            raise ValueError("%r is not a Stage 4 diagnostic code; the set is "
                             "closed so that every refusal is testable" % code)
        self.code = code
        self.subject = subject
        self.detail = detail
        self.fatal = (code in FATAL_CODES) if fatal is None else bool(fatal)
        # Other mods implicated in the same problem: the duplicate's twin, the
        # other end of a conflict, the members of a cycle. Sorted, so two runs
        # over the same inputs produce byte-identical reports.
        self.related = tuple(sorted(related))

    def as_dict(self):
        return {"code": self.code, "subject": self.subject, "detail": self.detail,
                "fatal": self.fatal, "related": list(self.related)}

    def __repr__(self):
        return "%s[%s] %s: %s" % ("FATAL" if self.fatal else "note", self.code,
                                  self.subject, self.detail)


def sort_key(diagnostic):
    """A total order over diagnostics, so reports are byte-stable.

    Sorting by (subject, code, detail) rather than by discovery order is what
    makes two runs that enumerated the filesystem differently produce the same
    report.
    """
    return (str(diagnostic.subject), diagnostic.code, diagnostic.detail)


def fatal(diagnostics):
    return [d for d in diagnostics if d.fatal]


def summarise(diagnostics):
    ordered = sorted(diagnostics, key=sort_key)
    return {"total": len(ordered), "fatal": len(fatal(ordered)),
            "diagnostics": [d.as_dict() for d in ordered]}
