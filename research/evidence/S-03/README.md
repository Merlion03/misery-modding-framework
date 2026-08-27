# S-03 — `dump_xrefs_for_string.py`, proven on real data

Method S-03 (`plan.md` line 566): given a string, find every occurrence in the program's data and
list every xref to each occurrence — caller function, call-site address, reference type. This is
RF-04's mechanism: string anchors → xrefs → candidate functions.

## What is here

`coreuobject-summary.json` — one proof run against the real Shipping image, needle `"CoreUObject"`.
Reused the already-analyzed Ghidra project from T-05 (`D:\tools\ghidra-projects\T05-primary-default-analysis`,
`-process` + `-noanalysis`, no re-import, no re-analysis) rather than paying the 95-minute cost again.

The full JSONL (423 records, one per xref) is **not committed**: it lives at
`workspace/xrefs/coreuobject.jsonl` (gitignored, regenerable), and its sha256
(`10cbb96aea488bdc77567377d21d7e8ec333d57da97f5b6153575ac4f0167f34`) is recorded in the committed
summary so the run is verifiable without redistributing a derived dump. Same discipline as
`research/evidence/S-01/README.md`'s decision for `strings.jsonl`.

## What it found

39 literal occurrences of the byte string `CoreUObject`, giving 423 xref records across 364
distinct containing functions. 37 of the 39 occurrences are distinct values — 2 duplicate value
pairs at different addresses. The values include both short tokens (`CoreUObject`,
`/Script/CoreUObject`) and full UE source-path literals
(`D:\build\++UE5\Sync\Engine\Source\Runtime\CoreUObject\Private\...`), corroborating what S-01
already found: this build carries source-path diagnostic literals naming specific engine
translation units.

*(OBSERVED, confidence 0.99, oracle: `filesystem`, class P — fields `occurrence_count` (39),
`jsonl_records` (423), `distinct_containing_functions` (364) of the committed summary JSON, read
as written; a claim about what any one of those 423 xrefs at its own determinate offset MEANS
would be class I and is graded per-record inside the (uncommitted) JSONL itself, not here.
build_key=sha256:0eef3715244b467c830022c4260a0e2c29c7def1429cb34aa37fdf9b7e14a383.)*

## How to reproduce

```
D:\Tools\venv-research\Scripts\python.exe pyghidra_scripts\dump_xrefs_for_string.py ^
  --project-root D:\tools\ghidra-projects --project-name T05-primary-default-analysis ^
  --program /MISERY-Win64-Shipping.exe --needle CoreUObject ^
  --out research\evidence\S-03\coreuobject-summary.json --jsonl-out workspace\xrefs\coreuobject.jsonl
```
(run from PowerShell — Git Bash mangles the backslash-leading `D:\tools\...` project-root argument)

Determinism: verified by a second run. `occurrences=39 xrefs=423 distinct_functions=364` reproduced
exactly, and the re-run JSONL's sha256 matched the committed `jsonl_sha256` byte for byte
(`10cbb96aea488bdc77567377d21d7e8ec333d57da97f5b6153575ac4f0167f34`). The tool's own test suite
(`tests/test_dump_xrefs_for_string.py`) additionally covers argument handling, output-path guarding
and JSON/JSONL shape against a synthetic fixture standing in for the Ghidra API.
