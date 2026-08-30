#!/usr/bin/env python3
"""From a set of manifests to a load plan. The only layer that compares mods.

WHAT "FAIL CLOSED" MEANS HERE, PRECISELY
----------------------------------------
Two mods declare the same ``mod_id``. One of them appears first on disk. The
tempting implementation keeps that one and warns about the other -- and it is
wrong, because "first on disk" is not a decision anybody made. The user did not
choose it, the authors did not choose it, and it changes when a folder is
renamed. So a duplicate id removes BOTH claimants: an ambiguous identity is not
resolved, it is refused. The same reasoning governs an explicit conflict, where
"which of these two incompatible mods did the user actually want" is a question
only the user can answer.

EXCLUSION PROPAGATES
--------------------
A mod whose dependency was excluded cannot load either, and its dependents
cannot, transitively. Propagating is what makes the plan trustworthy: every mod
in ``load_order`` has every one of its required dependencies in ``load_order``
too, ahead of it. A plan that listed a mod whose dependency had been dropped
would be a plan that fails at execution time, which is the failure Stage 4
exists to move earlier.

DETERMINISM
-----------
The topological sort is Kahn's algorithm over a queue kept sorted by mod_id, so
among mods that are equally ready to load the order is by id -- never by disk
order, never by the order dependencies were typed into a manifest. Feed the same
manifests in any order and the plan is byte-identical; the tests assert exactly
that by shuffling.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import diagnostics as D                                            # noqa: E402


class LoadPlan(object):
    """The answer: what loads, in what order, and why everything else does not."""

    __slots__ = ("load_order", "excluded", "diagnostics", "manifests")

    def __init__(self, load_order, excluded, diagnostics, manifests):
        self.load_order = load_order        # list of mod_id, in load order
        self.excluded = excluded            # {mod_id_or_folder: [codes]}
        self.diagnostics = sorted(diagnostics, key=D.sort_key)
        self.manifests = manifests          # {mod_id: Manifest} for the accepted

    @property
    def ok(self):
        """True when nothing was refused. A plan can be usable without being ok:
        two independent mods where one is broken still yields a valid plan for
        the other, and saying so is more useful than an all-or-nothing verdict."""
        return not self.excluded

    def as_dict(self):
        return {
            "load_order": list(self.load_order),
            "excluded": {k: sorted(v) for k, v in sorted(self.excluded.items())},
            "ok": self.ok,
            "diagnostics": D.summarise(self.diagnostics),
            "manifests": {mod_id: self.manifests[mod_id].as_dict()
                          for mod_id in sorted(self.manifests)},
        }

    def __repr__(self):
        return "LoadPlan(load_order=%r, excluded=%r)" % (self.load_order,
                                                         sorted(self.excluded))


def _index_by_id(discovered, out, excluded):
    """Group accepted manifests by mod_id, refusing every duplicated id.

    Both claimants are dropped. See the module docstring: picking one would be
    picking whichever the filesystem happened to hand over first.
    """
    by_id = {}
    for entry in discovered:
        # Carry EVERY discovery-time diagnostic into the plan, accepted or not.
        # An earlier version recorded only the exclusion CODES here, so the plan
        # knew a folder was refused but had lost the sentence explaining why --
        # a load plan that cannot say why a mod is missing is exactly the
        # untrustworthy artefact this stage exists to avoid.
        out.extend(entry.diagnostics)
        # Grouped by what the folder CLAIMED, not by what validated. Grouping by
        # validated manifests only meant a duplicate paired with any other
        # failure was never reported as a duplicate: the broken twin was filed
        # under its own id as "malformed", which then evicted the healthy owner
        # of that id through the shared `excluded` map -- under a code that
        # named the wrong problem entirely.
        if entry.declared_mod_id:
            by_id.setdefault(entry.declared_mod_id, []).append(entry)
        else:
            codes = sorted({d.code for d in entry.diagnostics if d.fatal})
            excluded.setdefault(entry.identity,
                                []).extend(codes or [D.MALFORMED_MANIFEST])

    accepted = {}
    for mod_id in sorted(by_id):
        entries = by_id[mod_id]
        if len(entries) > 1:
            folders = sorted(e.folder for e in entries)
            out.append(D.Diagnostic(
                D.DUPLICATE_MOD_ID, mod_id,
                "declared by %d folders (%s). mod_id is the authoritative "
                "identity, so this is one mod claiming to be two -- or two mods "
                "claiming one identity. EVERY claimant is refused: keeping "
                "whichever the filesystem returned first would make the outcome "
                "depend on folder order. This holds even when only one of them "
                "would otherwise have validated, because a folder that names an "
                "id has claimed it." % (len(entries), folders)))
            excluded.setdefault(mod_id, []).append(D.DUPLICATE_MOD_ID)
            continue
        entry = entries[0]
        if entry.manifest is None:
            codes = sorted({d.code for d in entry.diagnostics if d.fatal})
            excluded.setdefault(mod_id, []).extend(codes or [D.MALFORMED_MANIFEST])
            continue
        accepted[mod_id] = entry.manifest
    return accepted


def _check_dependencies(accepted, out, excluded):
    """Missing and version-incompatible dependencies, over the accepted set."""
    for mod_id in sorted(accepted):
        manifest = accepted[mod_id]
        for dependency in manifest.dependencies:
            target = accepted.get(dependency.mod_id)
            if target is None and dependency.mod_id in excluded:
                # Installed, but already refused. Telling the user their
                # dependency is "missing" would send them to download a mod they
                # already have; the useful answer names the refusal.
                out.append(D.Diagnostic(
                    D.DEPENDENCY_EXCLUDED, mod_id,
                    "requires %r %s, which IS installed but was itself refused "
                    "(%s)" % (dependency.mod_id, dependency.requirement,
                              ", ".join(sorted(set(excluded[dependency.mod_id])))),
                    related=[dependency.mod_id]))
                excluded.setdefault(mod_id, []).append(D.DEPENDENCY_EXCLUDED)
            elif target is None:
                out.append(D.Diagnostic(
                    D.MISSING_DEPENDENCY, mod_id,
                    "requires %r %s, which is not present in the load set"
                    % (dependency.mod_id, dependency.requirement),
                    related=[dependency.mod_id]))
                excluded.setdefault(mod_id, []).append(D.MISSING_DEPENDENCY)
            elif not dependency.requirement.matches(target.version):
                out.append(D.Diagnostic(
                    D.INCOMPATIBLE_DEPENDENCY_VERSION, mod_id,
                    "requires %r %s but the installed %r is %s"
                    % (dependency.mod_id, dependency.requirement,
                       dependency.mod_id, target.version),
                    related=[dependency.mod_id]))
                excluded.setdefault(mod_id, []).append(
                    D.INCOMPATIBLE_DEPENDENCY_VERSION)
        for dependency in manifest.optional_dependencies:
            target = accepted.get(dependency.mod_id)
            if target is None:
                # Absent optional dependency: informational, changes nothing.
                out.append(D.Diagnostic(
                    D.OPTIONAL_DEPENDENCY_ABSENT, mod_id,
                    "optional dependency %r is not installed" % dependency.mod_id,
                    related=[dependency.mod_id]))
            elif not dependency.requirement.matches(target.version):
                # PRESENT but incompatible is NOT optional. The author said "if
                # this is here, I need this version of it"; loading against a
                # version they excluded is worse than not loading at all.
                out.append(D.Diagnostic(
                    D.INCOMPATIBLE_DEPENDENCY_VERSION, mod_id,
                    "optional dependency %r is installed at %s, which its "
                    "requirement %s excludes. An optional dependency that is "
                    "PRESENT is not optional -- the mod would run against a "
                    "version it declared unusable."
                    % (dependency.mod_id, target.version, dependency.requirement),
                    related=[dependency.mod_id]))
                excluded.setdefault(mod_id, []).append(
                    D.INCOMPATIBLE_DEPENDENCY_VERSION)


def _check_conflicts(accepted, out, excluded):
    """Explicit conflicts. Both sides are refused, never one."""
    pairs = set()
    for mod_id in sorted(accepted):
        manifest = accepted[mod_id]
        for conflict in manifest.conflicts:
            other = accepted.get(conflict.mod_id)
            if other is None or not conflict.applies_to(other.version):
                continue
            pairs.add(tuple(sorted((mod_id, conflict.mod_id))))
    for left, right in sorted(pairs):
        out.append(D.Diagnostic(
            D.EXPLICIT_CONFLICT, left,
            "declared incompatible with %r (or vice versa). Both are refused: "
            "only the user can decide which of two mods that say they cannot "
            "coexist should be the one that loads." % right,
            related=[right]))
        out.append(D.Diagnostic(
            D.EXPLICIT_CONFLICT, right,
            "declared incompatible with %r (or vice versa). Both are refused: "
            "only the user can decide which of two mods that say they cannot "
            "coexist should be the one that loads." % left,
            related=[left]))
        excluded.setdefault(left, []).append(D.EXPLICIT_CONFLICT)
        excluded.setdefault(right, []).append(D.EXPLICIT_CONFLICT)


def _strongly_connected(nodes, edges):
    """Tarjan's SCC, iterative and deterministic.

    Iterative because a deep dependency chain would otherwise be bounded by
    Python's recursion limit, and a mod set that is legal but deep must not
    crash the resolver. Deterministic because both the outer iteration and each
    node's successors are sorted.
    """
    index = {}
    low = {}
    on_stack = {}
    stack = []
    result = []
    counter = [0]

    for start in sorted(nodes):
        if start in index:
            continue
        work = [(start, iter(sorted(edges.get(start, ()))))]
        index[start] = low[start] = counter[0]
        counter[0] += 1
        stack.append(start)
        on_stack[start] = True
        while work:
            node, successors = work[-1]
            advanced = False
            for successor in successors:
                if successor not in nodes:
                    continue
                if successor not in index:
                    index[successor] = low[successor] = counter[0]
                    counter[0] += 1
                    stack.append(successor)
                    on_stack[successor] = True
                    work.append((successor, iter(sorted(edges.get(successor, ())))))
                    advanced = True
                    break
                if on_stack.get(successor):
                    low[node] = min(low[node], index[successor])
            if advanced:
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])
            if low[node] == index[node]:
                component = []
                while True:
                    member = stack.pop()
                    on_stack[member] = False
                    component.append(member)
                    if member == node:
                        break
                result.append(sorted(component))
    return sorted(result)


def _check_cycles(accepted, out, excluded):
    """Every dependency cycle, reported with its members.

    A self-dependency is a one-node cycle and is caught by the self-loop test,
    not by component size -- Tarjan reports a lone node as its own component
    whether or not it points at itself.
    """
    nodes = set(accepted) - set(excluded)
    edges = {}
    for mod_id in nodes:
        # Optional dependencies are edges too when the target is present: they
        # order the load, so they can close a cycle just as a required one can.
        edges[mod_id] = sorted({d.mod_id for d in accepted[mod_id].all_dependencies
                                if d.mod_id in nodes})
    for component in _strongly_connected(nodes, edges):
        is_cycle = len(component) > 1 or component[0] in edges.get(component[0], ())
        if not is_cycle:
            continue
        # The members, and the edges that actually exist between them. The
        # first version joined the ALPHABETICALLY SORTED component with " -> "
        # and presented it as the dependency chain, so a cycle a->c->b->a was
        # reported as "a -> b -> c -> a" -- naming two edges that do not exist
        # and sending anyone debugging it to the wrong manifest.
        real_edges = ["%s -> %s" % (m, target) for m in component
                      for target in edges.get(m, ()) if target in set(component)]
        for member in component:
            out.append(D.Diagnostic(
                D.DEPENDENCY_CYCLE, member,
                "is part of a dependency cycle among {%s}. The edges between "
                "them are: %s. No order satisfies 'dependencies load first' for "
                "any member, so every member is refused."
                % (", ".join(component), "; ".join(sorted(real_edges))),
                related=[m for m in component if m != member]))
            excluded.setdefault(member, []).append(D.DEPENDENCY_CYCLE)


def _propagate_exclusions(accepted, out, excluded):
    """A mod whose required dependency is gone cannot load either.

    Repeated to a fixed point, because dropping a mod can drop its dependents,
    which can drop theirs. Each round is computed over a sorted set so the
    diagnostics come out in the same order every time.
    """
    while True:
        newly = []
        for mod_id in sorted(set(accepted) - set(excluded)):
            for dependency in accepted[mod_id].dependencies:
                if dependency.mod_id in excluded:
                    newly.append((mod_id, dependency.mod_id))
                    break
        if not newly:
            return
        for mod_id, cause in newly:
            out.append(D.Diagnostic(
                D.DEPENDENCY_EXCLUDED, mod_id,
                "required dependency %r was itself refused, so this mod cannot "
                "load. Listing it would produce a plan that fails at execution "
                "time -- which is the failure this stage exists to move earlier."
                % cause,
                related=[cause]))
            excluded.setdefault(mod_id, []).append(D.DEPENDENCY_EXCLUDED)


def _topological_order(accepted, excluded):
    """Kahn's algorithm with a deterministic ready set.

    The ready set is sorted every round rather than kept in a heap, because the
    sets are small and an explicit ``sorted`` is impossible to misread. Among
    mods that are equally ready, the tie-break is mod_id -- not folder name and
    not discovery order, so the plan cannot shift when a folder is renamed.
    """
    live = sorted(set(accepted) - set(excluded))
    prerequisites = {}
    dependents = {mod_id: [] for mod_id in live}
    for mod_id in live:
        needed = sorted({d.mod_id for d in accepted[mod_id].all_dependencies
                         if d.mod_id in dependents})
        prerequisites[mod_id] = set(needed)
        for target in needed:
            dependents[target].append(mod_id)

    ready = sorted(m for m in live if not prerequisites[m])
    order = []
    while ready:
        mod_id = ready.pop(0)
        order.append(mod_id)
        for dependent in sorted(dependents[mod_id]):
            prerequisites[dependent].discard(mod_id)
            if not prerequisites[dependent]:
                ready.append(dependent)
                ready.sort()
    # Anything left would be in a cycle, and cycles were already excluded.
    # Asserting rather than returning a partial order: a silent short plan is
    # exactly the "partially accepted" outcome this stage forbids.
    assert len(order) == len(live), (
        "topological sort dropped %s; cycles must be excluded before ordering"
        % sorted(set(live) - set(order)))
    return order


def resolve(discovered):
    """Discovery output -> a deterministic :class:`LoadPlan`.

    The order of the checks is deliberate. Identity is settled first, because
    every later question is asked about a mod_id. Then dependencies and
    conflicts, which are statements about the accepted set. Then cycles, over
    what survives. Then propagation, which needs every other exclusion to
    already be known. Ordering last, over a set with no cycles left in it.
    """
    out = []
    excluded = {}

    accepted = _index_by_id(discovered, out, excluded)
    _check_dependencies(accepted, out, excluded)
    _check_conflicts(accepted, out, excluded)
    _check_cycles(accepted, out, excluded)
    _propagate_exclusions(accepted, out, excluded)

    order = _topological_order(accepted, excluded)
    live = {mod_id: accepted[mod_id] for mod_id in order}
    return LoadPlan(order, {k: sorted(set(v)) for k, v in excluded.items()},
                    out, live)


def plan_from_root(root, container_reader=None, check_artifacts=True):
    """The whole read-only pipeline: discover, validate, resolve."""
    import discovery                                               # noqa: PLC0415
    report, found = discovery.scan(root, container_reader, check_artifacts)
    plan = resolve(found)
    return plan, report
