#!/usr/bin/env python3
"""The developer console foundation.

WHAT "FOUNDATION" MEANS HERE
----------------------------
A command registry, an argument convention, a deterministic renderer, and the
built-in commands that answer the questions the stage is required to answer. It
is not a UI. There is no key binding, no overlay and no text box, because
drawing anything inside MISERY needs engine work that has not been researched --
and a console that looked finished but could not be opened would be the same
dishonesty as an input registry that silently never fires.

What exists is the part that has to be right regardless of how it is eventually
displayed: the commands, their output shape, and the ownership rules for
commands a MOD contributes.

THE SEVEN QUESTIONS
-------------------
The stage requires the tooling to be able to explain, at minimum:

    discovered mods, resolved load order, mod state, dependency/conflict
    failure, registered items, owned assets/resources, structured subsystem
    errors

Each is a built-in command below, and each one is answered from live platform
state rather than from anything cached at startup -- a console that shows what
was true at boot is worse than none, because it is believed.

OUTPUT IS DATA
--------------
Every command returns a structure; rendering to text happens once, in one place.
That way the same command can serve a future in-game overlay, a log file and a
test, and the test can assert on values rather than on how they were spelled.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import errors as E                                                 # noqa: E402
import modid as _modid                                             # noqa: E402

MAX_COMMANDS_PER_MOD = 32
NAME_SEPARATOR = ":"


class Command(object):
    __slots__ = ("name", "summary", "handler", "owner_id", "token")

    def __init__(self, name, summary, handler, owner_id, token):
        self.name = name
        self.summary = summary
        self.handler = handler
        self.owner_id = owner_id
        self.token = token

    def as_dict(self):
        return {"name": self.name, "summary": self.summary,
                "owner": self.owner_id or "platform"}


class Console(object):
    """Commands, and the platform state they read."""

    def __init__(self, platform, plan=None, discovery_report=None):
        self.platform = platform
        self.plan = plan                          # the Stage 4 LoadPlan
        self.discovery_report = discovery_report  # the Stage 4 scan report
        self._commands = {}
        self._counts = {}
        self._register_builtins()

    # ---- registry --------------------------------------------------------
    def _builtin(self, name, summary, handler):
        self._commands[name] = Command(name, summary, handler, None, None)

    def register(self, owner, name, summary, handler):
        """A mod contributes a command, in its own namespace, owned by it."""
        if not isinstance(name, str) or NAME_SEPARATOR not in name:
            raise E.PlatformError(E.SUB_CONSOLE, E.E_INVALID_ARGUMENT,
                                  "command name %r must be '<mod_id>%s<name>'"
                                  % (name, NAME_SEPARATOR), owner.mod_id)
        prefix, _, local = name.partition(NAME_SEPARATOR)
        if prefix != owner.mod_id or not _modid.PATTERN.match(local or ""):
            raise E.PlatformError(
                E.SUB_CONSOLE, E.E_INVALID_ARGUMENT,
                "%r may only register commands under %r%s"
                % (owner.mod_id, owner.mod_id, NAME_SEPARATOR), owner.mod_id)
        if name in self._commands:
            raise E.PlatformError(E.SUB_CONSOLE, E.E_ALREADY_EXISTS,
                                  "command %r already exists" % name,
                                  owner.mod_id)
        if self._counts.get(owner.mod_id, 0) >= MAX_COMMANDS_PER_MOD:
            raise E.PlatformError(E.SUB_CONSOLE, E.E_LIMIT_EXCEEDED,
                                  "a mod may register at most %d commands"
                                  % MAX_COMMANDS_PER_MOD, owner.mod_id)
        token = owner.token(handler, "console_command", name)
        self._commands[name] = Command(name, summary, None, owner.mod_id, token)
        self._counts[owner.mod_id] = self._counts.get(owner.mod_id, 0) + 1

        def release():
            token.revoke()
            self._commands.pop(name, None)
            self._counts[owner.mod_id] = max(
                0, self._counts.get(owner.mod_id, 1) - 1)
        return owner.own("console_command", name, release, summary)

    def commands(self):
        return [self._commands[name].as_dict() for name in sorted(self._commands)]

    # ---- execution -------------------------------------------------------
    def run(self, line):
        """Execute one console line. Never raises; returns a result structure."""
        if not isinstance(line, str) or not line.strip():
            return {"ok": False, "error": "empty command"}
        parts = line.split()
        name, args = parts[0], parts[1:]
        command = self._commands.get(name)
        if command is None:
            return {"ok": False, "error": "unknown command %r" % name,
                    "hint": "try 'help'"}
        try:
            if command.token is not None:
                called, result = command.token.invoke(args)
                if not called:
                    # The owning mod was unloaded between listing and running.
                    return {"ok": False,
                            "error": "command %r is no longer available: its mod "
                                     "was unloaded" % name}
            else:
                result = command.handler(args)
            return {"ok": True, "command": name, "result": result}
        except E.PlatformError as error:
            return {"ok": False, "command": name, "error": error.as_dict()}
        except Exception as error:                                 # noqa: BLE001
            return {"ok": False, "command": name,
                    "error": {"detail": "%s: %s" % (type(error).__name__, error)}}

    # ---- the required built-ins -----------------------------------------
    def _register_builtins(self):
        self._builtin("help", "list commands", self._cmd_help)
        self._builtin("mods", "discovered mods and their state", self._cmd_mods)
        self._builtin("loadorder", "the resolved load order", self._cmd_loadorder)
        self._builtin("why", "why a mod is not loaded", self._cmd_why)
        self._builtin("owned", "what a mod owns", self._cmd_owned)
        self._builtin("items", "registered items, by mod", self._cmd_items)
        self._builtin("errors", "structured subsystem errors", self._cmd_errors)
        self._builtin("caps", "API version and capabilities", self._cmd_caps)
        self._builtin("events", "declared events and subscriber counts",
                      self._cmd_events)
        self._builtin("services", "published services and their consumers",
                      self._cmd_services)
        self._builtin("input", "registered input actions", self._cmd_input)
        self._builtin("settings", "declared settings, by mod", self._cmd_settings)
        self._builtin("log", "recent log records", self._cmd_log)

    def _cmd_help(self, _args):
        return {"commands": self.commands()}

    def _cmd_mods(self, _args):
        rows = []
        for entry in self.platform.mods():
            rows.append({"mod_id": entry["mod_id"], "state": entry["state"],
                         "order": entry["load_order_index"],
                         "error": (entry["error"] or {}).get("name")})
        discovered = None
        if self.discovery_report is not None:
            discovered = self.discovery_report.get("folders_examined")
        return {"mods": rows, "folders_examined": discovered}

    def _cmd_loadorder(self, _args):
        if self.plan is None:
            return {"load_order": [entry["mod_id"] for entry in
                                   self.platform.mods()],
                    "source": "host (no Stage 4 plan attached)"}
        return {"load_order": list(self.plan.load_order),
                "excluded": {k: sorted(v) for k, v in
                             sorted(self.plan.excluded.items())},
                "source": "Stage 4 load plan"}

    def _cmd_why(self, args):
        """Dependency and conflict failures, named. The question a user asks."""
        if self.plan is None:
            return {"error": "no load plan is attached"}
        wanted = args[0] if args else None
        rows = []
        for diagnostic in self.plan.diagnostics:
            if wanted and diagnostic.subject != wanted:
                continue
            rows.append({"mod_id": diagnostic.subject, "code": diagnostic.code,
                         "fatal": diagnostic.fatal, "detail": diagnostic.detail,
                         "related": list(diagnostic.related)})
        return {"subject": wanted, "diagnostics": rows,
                "excluded": {k: sorted(v) for k, v in
                             sorted(self.plan.excluded.items())}}

    def _cmd_owned(self, args):
        rows = []
        for entry in self.platform.mods():
            if args and entry["mod_id"] != args[0]:
                continue
            rows.append({"mod_id": entry["mod_id"], "state": entry["state"],
                         "owned": entry["owned"], "teardown": entry["teardown"]})
        return {"mods": rows}

    def _cmd_items(self, args):
        rows = []
        for entry in self.platform.mods():
            if args and entry["mod_id"] != args[0]:
                continue
            owned = entry["owned"] or {}
            items = (owned.get("resources") or {}).get("item") or {}
            rows.append({"mod_id": entry["mod_id"],
                         "held": items.get("held", []),
                         "released": items.get("released", [])})
        return {"items": rows,
                "backend_attached": self.platform.items_backend is not None}

    def _cmd_errors(self, _args):
        return {"errors": self.platform.errors()}

    def _cmd_caps(self, _args):
        diagnostics = self.platform.diagnostics()
        return {"api_version": diagnostics["api_version"],
                "capabilities": diagnostics["capabilities"],
                "granted": {entry["mod_id"]: entry["capabilities"]
                            for entry in self.platform.mods()
                            if entry["capabilities"]}}

    def _cmd_events(self, _args):
        return self.platform.events.summary()

    def _cmd_services(self, _args):
        return self.platform.services.summary()

    def _cmd_input(self, _args):
        return self.platform.input.summary()

    def _cmd_settings(self, args):
        if args:
            return {"mod_id": args[0],
                    "schema": self.platform.settings.schema_for(args[0]),
                    "values": self.platform.settings.all_for(args[0])}
        return self.platform.settings.summary()

    def _cmd_log(self, args):
        count = 20
        if args and args[0].isdigit():
            count = min(200, int(args[0]))
        return {"records": [r.as_dict() for r in
                            self.platform.log_router.buffer.tail(count)]}


def render(result):
    """One place that turns a command result into text.

    Kept separate so the same command can serve a test, a log file and whatever
    surface eventually displays it, without any of them re-deciding the wording.
    """
    if not result.get("ok", True) and "error" in result:
        error = result["error"]
        detail = error if isinstance(error, str) else error.get("detail", str(error))
        return "error: %s" % detail
    payload = result.get("result", result)
    lines = []

    def emit(prefix, value):
        if isinstance(value, dict):
            for key in sorted(value):
                emit("%s%s." % (prefix, key), value[key])
        elif isinstance(value, list):
            if not value:
                lines.append("%s(none)" % prefix)
            for index, item in enumerate(value):
                emit("%s[%d]." % (prefix.rstrip("."), index), item)
        else:
            lines.append("%s %s" % (prefix.rstrip("."), value))

    emit("", payload)
    return "\n".join(lines)
