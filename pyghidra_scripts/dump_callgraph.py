#!/usr/bin/env python3
"""S-05 -- callers/callees N levels from an address (plan.md §7.3 S-05).

What this walks, and how edges are found
-------------------------------------------
Two different Ghidra facts are used, one per direction, because each is the
authoritative source for that direction and each naturally yields real
call-site addresses (the task requires them, and neither
``Function.getCalledFunctions``/``getCallingFunctions`` alone provides one --
they return a bare ``Set<Function>``, no site information):

* **Callees (outgoing)** -- every instruction inside a function's own body is
  scanned; an instruction whose ``FlowType.isCall()`` is true is a call site.
  If Ghidra resolved at least one flow target (``Instruction.getFlows()``
  non-empty), each resolved target is looked up for its containing function
  and becomes a real edge. If ``getFlows()`` is EMPTY for a call-type
  instruction, Ghidra could not resolve a target at all (a genuinely
  indirect call through a register/computed address analysis did not
  narrow down) -- this becomes an edge with ``indirect: true`` and
  ``callee: null``, per the task's own definition of that flag ("no
  resolvable target"), rather than being silently dropped.
* **Callers (incoming)** -- every reference TO the function's entry point is
  read via the reference manager (the same mechanism S-03 uses for string
  xrefs), filtered to call-type references; each reference's ``fromAddress``
  is the call site, and the function containing it (if any) is the caller.
  A reference existing at all means Ghidra resolved SOME target for it (by
  definition it points here), so this direction cannot itself discover
  "an indirect call into an unknown function" -- that limitation is
  symmetric with the outgoing direction's own blind spot (an indirect call
  Ghidra could not resolve produces no reference anywhere, in either
  direction) and is stated here rather than glossed over.

Depth and recursion
--------------------
Two SEPARATE visited-sets, one per direction (a function can legitimately be
both an ancestor and a descendant of another in a real call graph, e.g. via
a cycle, and conflating the two visited-sets would under-report one
direction the first time a node is shared). BFS one level at a time, capped
at EXACTLY ``--depth`` levels; a node already visited in its own direction is
not re-expanded (breaks recursion), but an edge INTO an already-visited node
is still recorded (so a cycle shows up as an edge, not a gap).

``is_leaf`` -- whether a node has zero outgoing call-type instructions in its
own body (computed for every discovered node, not only ones expanded in the
callee direction, so the field means the same thing regardless of which
direction found the node).

Run only with ``D:\\Tools\\venv-research\\Scripts\\python.exe``.

CLI
---
    python pyghidra_scripts/dump_callgraph.py --address 140f4d8e0 --depth 2 \\
        --out research/evidence/S-05/callgraph-140f4d8e0-d2.json
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import _pyghidra_runner as runner  # noqa: E402

GENERATOR_NAME = "pyghidra_scripts/dump_callgraph.py"
GENERATOR_VERSION = "1.0.0"

QUESTION = (
    "plan.md §7.3 S-05: walking N levels of callers and callees from a seed "
    "address, what is the graph (nodes with leaf/thunk status, edges with "
    "call-site addresses, indirect calls flagged rather than dropped)?"
)

DIRECTIONS = ("both", "callers", "callees")


# --------------------------------------------------------------------------- #
# core logic -- narrow interfaces, so tests can fake them without a real JVM
# --------------------------------------------------------------------------- #

def outgoing_call_edges(listing: Any, function_manager: Any, func: Any) -> list[tuple[dict, Any]]:
    """(edge, callee-function-or-None) for every call-type instruction in
    *func*'s own body. *listing* needs ``getInstructions(body, True)``;
    each instruction needs ``getFlowType()``, ``getFlows()``,
    ``getMinAddress()``. *function_manager* needs ``getFunctionContaining``.
    """
    caller_entry = str(func.getEntryPoint())
    out = []
    for instr in listing.getInstructions(func.getBody(), True):
        flow_type = instr.getFlowType()
        if not flow_type.isCall():
            continue
        call_site = str(instr.getMinAddress())
        flows = instr.getFlows()
        ref_type = runner.classify_ref_type(flow_type)
        if len(flows) == 0:
            out.append(({
                "caller": caller_entry, "callee": None, "call_site": call_site,
                "indirect": True, "reference_type": ref_type,
            }, None))
            continue
        for target in flows:
            callee_func = function_manager.getFunctionContaining(target)
            out.append(({
                "caller": caller_entry,
                "callee": str(callee_func.getEntryPoint()) if callee_func else None,
                "callee_target_address": str(target),
                "call_site": call_site,
                "indirect": callee_func is None,
                "reference_type": ref_type,
            }, callee_func))
    return out


def incoming_call_edges(reference_manager: Any, function_manager: Any, func: Any) -> list[tuple[dict, Any]]:
    """(edge, caller-function-or-None) for every call-type reference TO
    *func*'s entry point. *reference_manager* needs
    ``getReferencesTo(addr)``; each ref needs ``getFromAddress()``,
    ``getReferenceType()``.
    """
    callee_entry = str(func.getEntryPoint())
    out = []
    for ref in reference_manager.getReferencesTo(func.getEntryPoint()):
        rt = ref.getReferenceType()
        if not rt.isCall():
            continue
        from_addr = ref.getFromAddress()
        caller_func = function_manager.getFunctionContaining(from_addr)
        out.append(({
            "caller": str(caller_func.getEntryPoint()) if caller_func else None,
            "callee": callee_entry,
            "call_site": str(from_addr),
            # A reference TO this function, by definition, names a resolved
            # target -- see module docstring for why this direction cannot
            # itself surface "indirect, target unknown" the way the
            # outgoing direction does.
            "indirect": False,
            "reference_type": runner.classify_ref_type(rt),
        }, caller_func))
    return out


def is_leaf(listing: Any, func: Any) -> bool:
    """True if *func* has zero call-type instructions in its own body."""
    for instr in listing.getInstructions(func.getBody(), True):
        if instr.getFlowType().isCall():
            return False
    return True


def node_record(program: Any, listing: Any, func: Any, depth: int) -> dict:
    brief = runner.describe_function_brief(func)
    brief["is_leaf"] = is_leaf(listing, func)
    brief["depth"] = depth
    return brief


def walk_callgraph(
    program: Any,
    seed_func: Any,
    depth: int,
    direction: str = "both",
) -> tuple[dict[str, dict], list[dict]]:
    """BFS *depth* levels out from *seed_func* in *direction*
    ("both"/"callers"/"callees"). Returns (nodes-by-address, edges).

    Two independent visited-sets (one per direction) so a node reachable as
    both an ancestor and a descendant is expanded in each direction it
    appears in, and neither direction stops early because the other already
    saw the address. Edges into an already-visited node are still recorded
    (a cycle becomes a repeated edge, not a missing one); a node is never
    expanded a second time in its own direction (that is what bounds the
    walk on a cyclic graph).
    """
    if direction not in DIRECTIONS:
        raise ValueError("direction must be one of %s, got %r" % (DIRECTIONS, direction))
    listing = program.getListing()
    fm = program.getFunctionManager()
    rm = program.getReferenceManager()

    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    edge_seen: set[tuple] = set()

    def record_node(func, at_depth) -> str:
        entry = str(func.getEntryPoint())
        existing = nodes.get(entry)
        if existing is None:
            nodes[entry] = node_record(program, listing, func, at_depth)
        elif at_depth < existing["depth"]:
            existing["depth"] = at_depth
        return entry

    def record_edge(edge: dict) -> None:
        key = (edge["caller"], edge["callee"], edge["call_site"], edge["indirect"])
        if key in edge_seen:
            return
        edge_seen.add(key)
        edges.append(edge)

    seed_entry = record_node(seed_func, 0)

    if direction in ("both", "callees"):
        visited = {seed_entry}
        frontier = [seed_func]
        for level in range(depth):
            next_frontier = []
            for func in frontier:
                for edge, callee_func in outgoing_call_edges(listing, fm, func):
                    record_edge(edge)
                    if callee_func is None:
                        continue
                    entry = str(callee_func.getEntryPoint())
                    if entry not in visited:
                        visited.add(entry)
                        record_node(callee_func, level + 1)
                        next_frontier.append(callee_func)
            frontier = next_frontier
            if not frontier:
                break

    if direction in ("both", "callers"):
        visited = {seed_entry}
        frontier = [seed_func]
        for level in range(depth):
            next_frontier = []
            for func in frontier:
                for edge, caller_func in incoming_call_edges(rm, fm, func):
                    record_edge(edge)
                    if caller_func is None:
                        continue
                    entry = str(caller_func.getEntryPoint())
                    if entry not in visited:
                        visited.add(entry)
                        record_node(caller_func, level + 1)
                        next_frontier.append(caller_func)
            frontier = next_frontier
            if not frontier:
                break

    return nodes, edges


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dump_callgraph.py",
        description=("S-05: walk callers/callees N levels from an address "
                    "(plan.md §7.3)."),
    )
    parser.add_argument("--address", required=True, metavar="ADDR-OR-NAME",
                        help="hex address or exact function name to seed the walk from")
    parser.add_argument("--depth", type=int, required=True, metavar="N",
                        help="levels to walk in each requested direction (>= 0)")
    parser.add_argument("--direction", choices=DIRECTIONS, default="both",
                        help="which direction(s) to walk (default: both)")
    parser.add_argument("--out", required=True, help="JSON output path")
    runner.add_common_arguments(parser)
    return parser


@runner.handle_prerequisite_errors
def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    if args.depth < 0:
        raise ValueError("--depth must be >= 0, got %d" % args.depth)

    runner.pathguard.check_output_path(
        args.out, args.install_dir or runner.pathguard.CONFIGURED_INSTALL_ROOTS[0],
        what="--out")

    copy_record = None
    if not args.skip_copy_verification:
        copy_record = runner.verify_target_copy(args.target_copy, args.expect_sha256)

    generated_at = runner.recorded_at(args)

    with runner.open_program_from_args(args) as (project, program):
        seed_func = runner.resolve_function(program, args.address)
        nodes, edges = walk_callgraph(program, seed_func, args.depth, args.direction)
        program_name = program.getName()
        seed_entry = str(seed_func.getEntryPoint())

    nodes_sorted = [nodes[k] for k in sorted(nodes.keys())]
    edges_sorted = sorted(
        edges,
        key=lambda e: (e["call_site"], e["caller"] or "", e["callee"] or ""))

    indirect_count = sum(1 for e in edges_sorted if e["indirect"])
    unresolved_caller_count = sum(
        1 for e in edges_sorted if e["caller"] is None and not e["indirect"])

    document = {
        "generator": GENERATOR_NAME,
        "generator_version": GENERATOR_VERSION,
        "generated_at": generated_at,
        "question": QUESTION,
        "task": "plan.md §7.3 S-05",
        "build_key": runner.DEFAULT_BUILD_KEY if args.expect_sha256 == runner.DEFAULT_EXPECT_SHA256
                    else ("sha256:" + args.expect_sha256 if args.expect_sha256 else None),
        "target_copy": copy_record,
        "project": {"root": args.project_root, "name": args.project_name,
                   "program": args.program, "program_name": program_name},
        "seed": {"spec": args.address, "entry": seed_entry},
        "depth": args.depth,
        "direction": args.direction,
        "node_count": len(nodes_sorted),
        "edge_count": len(edges_sorted),
        "indirect_edge_count": indirect_count,
        "unresolved_caller_edge_count": unresolved_caller_count,
        "leaf_node_count": sum(1 for n in nodes_sorted if n["is_leaf"]),
        "nodes": nodes_sorted,
        "edges": edges_sorted,
    }

    out_path = runner.write_json_guarded(document, args.out, args.install_dir, "--out")
    print("seed=%s depth=%d direction=%s nodes=%d edges=%d indirect=%d"
         % (seed_entry, args.depth, args.direction, len(nodes_sorted),
            len(edges_sorted), indirect_count), file=sys.stderr)
    print("written: %s" % out_path, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
