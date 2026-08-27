# S-05 — `dump_callgraph.py`, proven on real data

Method S-05 (`plan.md` line 568): given a seed address and depth N, walk callers/callees N levels
out and emit the graph — nodes (address, name, leaf/thunk flag) and edges (caller, callee,
call-site, `indirect: true` for unresolved indirect calls rather than a silently dropped edge).
Reuses the T-05 Ghidra project, same as S-03/S-04.

## What is here

| File | Seed | Depth | Direction | Nodes | Edges |
|---|---|---|---|---|---|
| `callgraph-140f309c0-d1-callers-excerpt.json` | `140f309c0` (`caseD_1`) | 1 | callers | 25 | 25 |
| `callgraph-140f4d8e0-d2-both.json` | `140f4d8e0` | 2 | both | 2 | 1 |

The first run's `nodes`/`edges` are an EXCERPT (`nodes_are_excerpt`/`edges_are_excerpt` = true,
`nodes_full_count`/`edges_full_count` name the real totals, full data hashed via `full_sha256`) —
`caseD_1`'s 5612 incoming callers (S-04) make a full dump impractical to commit; the excerpt
mechanism is there specifically for exactly this case and is exercised by real data, not just a
unit test. The second run is small enough to be complete.

*(INFERRED, confidence 0.85, oracle: `binary-analysis`, class I — this is a summary claim about
what the tool produced across two runs, not a literal byte read at one determinate offset+length;
each individual node/edge in the underlying JSON carries its own address and is class P at that
level. Two independent methods: (1) the excerpt/full-count mechanism itself, checked against S-04's
independently-read `incoming_call_count` for the same seed (5612 callers + 1 seed node = 5613,
matching `nodes_full_count` exactly); (2) the depth-2 run's small, fully-enumerated graph (2 nodes,
1 edge) checked by hand against the raw JSON rather than trusted from the summary line. No claim
about what any node does. build_key=sha256:0eef3715244b467c830022c4260a0e2c29c7def1429cb34aa37fdf9b7e14a383.)*

## What this proves and does not prove

Proves the tool works end to end, including its excerpt path for a high-fan-in node — the kind of
node RF-05..RF-07's xref-chasing will hit routinely (a widely-called utility function is a common
false lead, and being able to see that a candidate has 5612 callers before decompiling all of them
is exactly the cheap first filter wave 2 needs). Does not itself identify any Unreal internal.

## How to reproduce

```
D:\Tools\venv-research\Scripts\python.exe pyghidra_scripts\dump_callgraph.py ^
  --project-root D:\tools\ghidra-projects --project-name T05-primary-default-analysis ^
  --program /MISERY-Win64-Shipping.exe --seed 140f309c0 --depth 1 --direction callers ^
  --out research\evidence\S-05\callgraph-140f309c0-d1-callers-excerpt.json
```
(PowerShell)

Not re-verified by a second run in this pass; `tests/test_dump_callgraph.py` covers depth-capping,
recursion (visited-set) handling, indirect-call flagging and output-path guarding against a
synthetic fixture.
