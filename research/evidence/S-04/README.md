# S-04 — `dump_function.py`, proven on real data

Method S-04 (`plan.md` line 567): given a function by address or name, dump its entry/size,
decompiled pseudocode, disassembly listing, and one level of incoming/outgoing calls. Reuses the
Ghidra project already analyzed for T-05 (`-process` + `-noanalysis`, no re-import).

## What is here

Four function dumps, picked as small, cheap smoke-test targets rather than the RTTI-attributed
functions originally proposed for this proof (none of these four addresses appear in
`research/evidence/S-10/rtti.jsonl` — say so plainly rather than implying otherwise):

| File | Entry | Ghidra name | Size | Decompile |
|---|---|---|---|---|
| `fun-140f309c0.json` | `140f309c0` | `caseD_1` (switch-table case) | 3 B | succeeded, plausible |
| `fun-140f4d8e0.json` | `140f4d8e0` | `FUN_140f4d8e0` | 43 B | succeeded, plausible |
| `fun-1414dc8d0.json` | `1414dc8d0` | `FUN_1414dc8d0` | 66 B | succeeded, plausible |
| `fun-1414e6930.json` | `1414e6930` | `FUN_1414e6930` | 19 B | succeeded, plausible |

Each dump's `decompile.sanity_check` (braces/parens balanced, non-empty, no error marker) passed,
and each carries real incoming/outgoing call data from the analyzed project — `caseD_1` alone has
5612 recorded incoming calls, a genuine shared switch-jump target, not a fabricated number.

*(INFERRED, confidence 0.85, oracle: `binary-analysis`, class I — this is a summary claim about
four dumps naming what the decompiler/call-graph output IS (real, sane, tool-produced), not a
literal byte read at one determinate offset+length, so class P does not apply here; the four
individual dumps themselves each carry their own offset (entry address) and length (size_bytes) in
their `function` field and are class P read at that level. Two independent methods for the summary
claim: (1) structural sanity check of the decompiler output (braces/parens balanced, non-empty, no
error marker) for all four; (2) cross-check of `caseD_1`'s reported 5612 incoming-call count
against S-05's independently-built callgraph for the same address (`research/evidence/S-05/
callgraph-140f309c0-d1-callers-excerpt.json`, `nodes_full_count` = 5613) — one node more, exactly
consistent with the seed node itself being counted alongside its 5612 callers, not a discrepancy.
No claim about what
any of these functions DOES semantically is made here — none of the four is currently correlated
with a named UE symbol. build_key=sha256:0eef3715244b467c830022c4260a0e2c29c7def1429cb34aa37fdf9b7e14a383.)*

## What this proves and does not prove

Proves the tool works end to end against the real image: real decompiler invocation, real
disassembly rows, real call-graph edges, sane JSON shape. Does NOT prove anything about Unreal
internals — that is wave 2's job (RF-04..RF-08), using S-04 as one of its instruments once RF-04
(S-03) has named a candidate function worth decompiling.

## How to reproduce

```
D:\Tools\venv-research\Scripts\python.exe pyghidra_scripts\dump_function.py ^
  --project-root D:\tools\ghidra-projects --project-name T05-primary-default-analysis ^
  --program /MISERY-Win64-Shipping.exe --address 140f309c0 ^
  --out research\evidence\S-04\fun-140f309c0.json
```
(PowerShell — see S-03's README for why)

Not re-verified by a second run in this pass; `tests/test_dump_function.py` (part of 92 passing
tests across S-03/S-04/S-05/the shared runner) covers argument handling, output-path guarding and
JSON shape against a synthetic fixture.
