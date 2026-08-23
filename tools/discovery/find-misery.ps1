<#
.SYNOPSIS
    Thin wrapper around tools/discovery/find_misery.py (plan.md 2, exit criterion 3 of M0).

.DESCRIPTION
    plan.md 2 names `tools/discovery/find-misery.ps1` as the entry point, while all the
    discovery logic lives in the Python implementation next to this file. This wrapper
    therefore does exactly two things and nothing else:

      1. picks an interpreter -- the canonical research venv
         D:\Tools\venv-research\Scripts\python.exe first, then the base interpreter
         C:\Python314\python.exe, then any `python` on PATH;
      2. forwards every argument through, unmodified, and propagates the exit code.

    Adding behaviour here would mean the PowerShell and Python entry points could
    disagree, and there would be two implementations of one algorithm to keep correct.

    find_misery.py uses the standard library only, so the base interpreter is a fully
    valid fallback for THIS script -- unlike the test suite and tools/kb/validate.py,
    which require the venv (requirements.txt, docs/toolchain.md 3.1).

.PARAMETER Arguments
    Passed straight to find_misery.py. See `find-misery.ps1 --help`.

.EXAMPLE
    .\tools\discovery\find-misery.ps1 --out research\builds\<build-id>\install.json

.EXAMPLE
    .\tools\discovery\find-misery.ps1 --install-dir 'D:\Games\Steam\steamapps\common\MISERY'

.NOTES
    Windows PowerShell 5.1 compatible: no '&&', no ternary operator, no null-coalescing.
    Exit codes come from find_misery.py: 0 validated find, 1 not found or validation
    failed, 2 usage or I/O error. This wrapper itself exits 127 when no interpreter
    could be found.
#>

[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $Arguments
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Preferred first. The venv is the canonical interpreter of the project
# (requirements.txt); C:\Python314 is only the base it was created from.
$candidates = @(
    'D:\Tools\venv-research\Scripts\python.exe',
    'C:\Python314\python.exe'
)

$python = $null
foreach ($candidate in $candidates) {
    if (Test-Path -LiteralPath $candidate -PathType Leaf) {
        $python = $candidate
        break
    }
}

if ($null -eq $python) {
    $onPath = Get-Command -Name 'python.exe' -CommandType Application -ErrorAction SilentlyContinue
    if ($null -ne $onPath) {
        $python = $onPath.Source
        Write-Warning "Neither interpreter from the toolchain was found; falling back to '$python' from PATH."
    }
}

if ($null -eq $python) {
    Write-Error "No Python interpreter found. Looked for: $($candidates -join ', '), then 'python.exe' on PATH. See docs/toolchain.md."
    exit 127
}

$script = Join-Path -Path $PSScriptRoot -ChildPath 'find_misery.py'
if (-not (Test-Path -LiteralPath $script -PathType Leaf)) {
    Write-Error "find_misery.py not found next to this wrapper (expected '$script')."
    exit 127
}

Write-Verbose "interpreter: $python"
Write-Verbose "script:      $script"

# $Arguments can legitimately be empty; splatting $null would pass a literal empty
# argument on 5.1, so the two cases are spelled out instead of using a ternary.
if ($null -eq $Arguments) {
    & $python $script
}
elseif ($Arguments.Count -eq 0) {
    & $python $script
}
else {
    & $python $script @Arguments
}

exit $LASTEXITCODE
