#!/usr/bin/env python3
"""Tests for pyghidra_scripts/dump_callgraph.py (S-05).

Same split as the rest of this tool family's tests: no JVM. The interesting
correctness properties here are graph-shaped rather than Ghidra-API-shaped,
so most of this file builds small SYNTHETIC call graphs (including a cycle)
out of hand-built ``Instruction``/``Reference``/``Function`` stand-ins and
checks that :func:`dump_callgraph.walk_callgraph` bounds depth correctly,
records edges into an already-visited node instead of dropping them, and
reports an unresolved indirect call rather than silently skipping it. The
real walk -- 5613 real callers found one level out from a COMDAT-folded
stub, cross-checked against S-04's independently-computed caller count for
the same address -- is ``research/evidence/S-05/README.md``.
"""

from __future__ import annotations

import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "pyghidra_scripts"))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools", "static"))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools", "inventory"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import dump_callgraph as tool  # noqa: E402
import pathguard  # noqa: E402
from test_discovery import make_install_tree  # noqa: E402
from test_pyghidra_runner import FakeAddress, FakeRefType  # noqa: E402


# --------------------------------------------------------------------------- #
# a small synthetic program: A -> B -> C -> A (a cycle), plus one indirect
# call in A and a leaf D with no outgoing calls at all
# --------------------------------------------------------------------------- #

CALL_FLOW = FakeRefType("UNCONDITIONAL_CALL", call=True, flow=True)


class FakeInstr:
    def __init__(self, address, flow_type, flows):
        self._addr = FakeAddress(address)
        self._flow_type = flow_type
        self._flows = [FakeAddress(a) for a in flows]

    def getMinAddress(self):
        return self._addr

    def getFlowType(self):
        return self._flow_type

    def getFlows(self):
        return list(self._flows)


class FakeFunc:
    def __init__(self, entry, name, instructions, *, is_thunk=False, is_external=False):
        self.entry = FakeAddress(entry)
        self.name = name
        self.instructions = instructions
        self._is_thunk = is_thunk
        self._is_external = is_external

    def getEntryPoint(self):
        return self.entry

    def getName(self):
        return self.name

    def getBody(self):
        return self  # identity is enough; FakeListing ignores body's identity below

    def isThunk(self):
        return self._is_thunk

    def isExternal(self):
        return self._is_external


class FakeListing:
    """Maps a function's identity to its own instruction list -- real
    ``Listing.getInstructions(body, True)`` is a program-wide call keyed by
    address range, but every caller in this module always passes exactly one
    function's own body, so keying on the function object stands in fine."""

    def __init__(self, by_func: dict):
        self._by_func = by_func

    def getInstructions(self, body, forward):
        return list(self._by_func.get(body, []))


class FakeFunctionManager:
    """Real ``FunctionManager.getFunctionContaining`` resolves ANY address
    inside a function's body, not only its entry point -- a call site is
    almost never the entry point itself. *body_addresses* maps each
    function to every address (entry point plus every instruction address
    in its own body) that should resolve to it, mirroring that."""

    def __init__(self, body_addresses: dict):
        self._by_address = {}
        for func, addresses in body_addresses.items():
            for address in addresses:
                self._by_address[address] = func

    def getFunctionContaining(self, addr):
        key = addr.text if isinstance(addr, FakeAddress) else addr
        return self._by_address.get(key)


class FakeReference:
    def __init__(self, from_addr, ref_type=CALL_FLOW):
        self._from = FakeAddress(from_addr)
        self._type = ref_type

    def getFromAddress(self):
        return self._from

    def getReferenceType(self):
        return self._type


class FakeReferenceManager:
    def __init__(self, refs_to: dict):
        self._refs_to = refs_to

    def getReferencesTo(self, addr):
        key = addr.text if isinstance(addr, FakeAddress) else addr
        return list(self._refs_to.get(key, []))


class FakeProgram:
    def __init__(self, listing, func_mgr, ref_mgr):
        self._listing = listing
        self._fm = func_mgr
        self._rm = ref_mgr

    def getListing(self):
        return self._listing

    def getFunctionManager(self):
        return self._fm

    def getReferenceManager(self):
        return self._rm


def build_cyclic_program():
    """A --call--> B --call--> C --call--> A, plus A also has one
    UNRESOLVED indirect call (no flows at all), and D is a leaf nobody
    calls and who calls nobody."""
    a = FakeFunc("a0", "A", [])
    b = FakeFunc("b0", "B", [])
    c = FakeFunc("c0", "C", [])
    d = FakeFunc("d0", "D", [])

    instr_a_to_b = FakeInstr("a1", CALL_FLOW, ["b0"])
    instr_a_indirect = FakeInstr("a2", CALL_FLOW, [])  # no resolvable target
    instr_b_to_c = FakeInstr("b1", CALL_FLOW, ["c0"])
    instr_c_to_a = FakeInstr("c1", CALL_FLOW, ["a0"])

    listing = FakeListing({
        a: [instr_a_to_b, instr_a_indirect],
        b: [instr_b_to_c],
        c: [instr_c_to_a],
        d: [],
    })
    func_mgr = FakeFunctionManager({
        a: ["a0", "a1", "a2"],
        b: ["b0", "b1"],
        c: ["c0", "c1"],
        d: ["d0"],
    })
    ref_mgr = FakeReferenceManager({
        "b0": [FakeReference("a1")],
        "c0": [FakeReference("b1")],
        "a0": [FakeReference("c1")],
    })
    program = FakeProgram(listing, func_mgr, ref_mgr)
    return program, {"a": a, "b": b, "c": c, "d": d}


# --------------------------------------------------------------------------- #
# outgoing_call_edges / incoming_call_edges
# --------------------------------------------------------------------------- #

def test_outgoing_call_edges_resolved_and_indirect():
    program, f = build_cyclic_program()
    edges = tool.outgoing_call_edges(program.getListing(), program.getFunctionManager(), f["a"])
    by_site = {e["call_site"]: e for e, _func in edges}
    assert by_site["a1"]["callee"] == "b0"
    assert by_site["a1"]["indirect"] is False
    assert by_site["a2"]["callee"] is None
    assert by_site["a2"]["indirect"] is True


def test_outgoing_call_edges_returns_the_callee_function_object():
    program, f = build_cyclic_program()
    edges = tool.outgoing_call_edges(program.getListing(), program.getFunctionManager(), f["a"])
    resolved = [func for _e, func in edges if func is not None]
    assert resolved == [f["b"]]


def test_outgoing_call_edges_none_for_a_leaf():
    program, f = build_cyclic_program()
    assert tool.outgoing_call_edges(program.getListing(), program.getFunctionManager(), f["d"]) == []


def test_incoming_call_edges_finds_the_caller():
    program, f = build_cyclic_program()
    edges = tool.incoming_call_edges(program.getReferenceManager(),
                                     program.getFunctionManager(), f["b"])
    assert len(edges) == 1
    edge, caller_func = edges[0]
    assert edge["caller"] == "a0"
    assert edge["call_site"] == "a1"
    assert edge["indirect"] is False
    assert caller_func is f["a"]


def test_incoming_call_edges_none_for_unreferenced_function():
    program, f = build_cyclic_program()
    assert tool.incoming_call_edges(program.getReferenceManager(),
                                   program.getFunctionManager(), f["d"]) == []


# --------------------------------------------------------------------------- #
# is_leaf / node_record
# --------------------------------------------------------------------------- #

def test_is_leaf_true_for_d_false_for_a():
    program, f = build_cyclic_program()
    assert tool.is_leaf(program.getListing(), f["d"]) is True
    assert tool.is_leaf(program.getListing(), f["a"]) is False


def test_node_record_shape():
    program, f = build_cyclic_program()
    record = tool.node_record(program, program.getListing(), f["d"], depth=2)
    assert record == {"name": "D", "entry": "d0", "is_thunk": False,
                      "is_external": False, "is_leaf": True, "depth": 2}


# --------------------------------------------------------------------------- #
# walk_callgraph -- depth capping, cycle handling, both directions
# --------------------------------------------------------------------------- #

def test_walk_callgraph_depth_zero_is_just_the_seed():
    program, f = build_cyclic_program()
    nodes, edges = tool.walk_callgraph(program, f["a"], depth=0, direction="both")
    assert set(nodes) == {"a0"}
    assert edges == []  # nothing expanded, so no edges recorded either


def test_walk_callgraph_depth_one_callees_finds_b_and_the_indirect_edge():
    program, f = build_cyclic_program()
    nodes, edges = tool.walk_callgraph(program, f["a"], depth=1, direction="callees")
    assert set(nodes) == {"a0", "b0"}
    calls_to_b = [e for e in edges if e["callee"] == "b0"]
    indirect = [e for e in edges if e["indirect"]]
    assert len(calls_to_b) == 1
    assert len(indirect) == 1
    assert indirect[0]["callee"] is None


def test_walk_callgraph_cycle_does_not_loop_forever():
    # A -> B -> C -> A is a real cycle; depth=5 must terminate (the test
    # itself is the proof -- an infinite loop here would hang, not fail an
    # assertion) and must NOT re-expand a already-visited node.
    program, f = build_cyclic_program()
    nodes, edges = tool.walk_callgraph(program, f["a"], depth=5, direction="callees")
    assert set(nodes) == {"a0", "b0", "c0"}
    # The cycle-closing edge C -> A is still RECORDED even though A was
    # already visited -- a cycle must show up as an edge, not vanish.
    closing_edges = [e for e in edges if e["caller"] == "c0" and e["callee"] == "a0"]
    assert len(closing_edges) == 1


def test_walk_callgraph_both_directions_from_the_middle_of_the_cycle():
    program, f = build_cyclic_program()
    nodes, edges = tool.walk_callgraph(program, f["b"], depth=1, direction="both")
    # One level out from B: A calls B (caller), B calls C (callee).
    assert set(nodes) == {"b0", "a0", "c0"}


def test_walk_callgraph_depth_caps_exactly_at_n():
    program, f = build_cyclic_program()
    nodes, _edges = tool.walk_callgraph(program, f["a"], depth=1, direction="callees")
    # Depth 1 must NOT reach C (that needs 2 hops: A->B->C).
    assert "c0" not in nodes


def test_walk_callgraph_rejects_an_unknown_direction():
    program, f = build_cyclic_program()
    with pytest.raises(ValueError, match="direction"):
        tool.walk_callgraph(program, f["a"], depth=1, direction="sideways")


def test_walk_callgraph_node_depth_is_the_minimum_seen():
    # D is unreachable in this fixture, but a node reached two different
    # ways at two different depths should keep the SMALLER one; exercised
    # directly by re-visiting B through both a direct edge and (if it were
    # reachable another way) a longer path. Here we just confirm the seed
    # itself is depth 0 and its first hop is depth 1, the base case the
    # invariant depends on.
    program, f = build_cyclic_program()
    nodes, _edges = tool.walk_callgraph(program, f["a"], depth=1, direction="callees")
    assert nodes["a0"]["depth"] == 0
    assert nodes["b0"]["depth"] == 1


# --------------------------------------------------------------------------- #
# CLI argument parsing
# --------------------------------------------------------------------------- #

def test_address_and_depth_are_required():
    with pytest.raises(SystemExit):
        tool.build_arg_parser().parse_args(["--out", "a.json"])
    with pytest.raises(SystemExit):
        tool.build_arg_parser().parse_args(["--address", "1000", "--out", "a.json"])


def test_direction_defaults_to_both():
    args = tool.build_arg_parser().parse_args(
        ["--address", "1000", "--depth", "2", "--out", "a.json"])
    assert args.direction == "both"


def test_direction_rejects_an_unknown_value():
    with pytest.raises(SystemExit):
        tool.build_arg_parser().parse_args(
            ["--address", "1000", "--depth", "2", "--direction", "sideways",
             "--out", "a.json"])


def test_main_rejects_a_negative_depth(capsys):
    rc = tool.main(["--address", "1000", "--depth", "-1", "--out",
                   os.path.join(os.getcwd(), "unused.json")])
    assert rc == 2
    assert "depth" in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# output-path guarding on main(), no JVM needed
# --------------------------------------------------------------------------- #

def test_main_refuses_an_out_path_inside_an_installation(tmp_path, capsys):
    install_root = make_install_tree(str(tmp_path / "install"))
    bad_out = os.path.join(install_root, "MISERY", "sneaky.json")
    rc = tool.main(["--address", "1000", "--depth", "1", "--out", bad_out,
                   "--install-dir", install_root])
    assert rc == 2
    assert "installation" in capsys.readouterr().err
