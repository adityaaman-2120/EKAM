<#
.SYNOPSIS
    Windows equivalent of `make check` — run before every commit and at the
    end of every phase. Does not depend on pre-commit being installed.

.DESCRIPTION
    Runs, in order, stopping at the first failure:
        ruff format .
        ruff check . --fix
        ruff check .
        pytest -q

    This exists because `ruff format` drifted across multiple phases on this
    machine even with .pre-commit-config.yaml present — two root causes, both
    now closed:
      1. the git hook was never installed (`.git\hooks\pre-commit` was
         missing; `pre-commit install` had never actually been run), so the
         committed config was never exercised;
      2. a bare `ruff` on PATH can resolve to an unrelated install (e.g. an
         Anaconda `ruff` 0.12.0) instead of the project-pinned version in
         .venv, and different ruff versions disagree on some rules. This
         script therefore calls the tools from `.venv` explicitly whenever a
         venv is present, falling back to PATH only if it is not — never a
         silently-wrong version.

.EXAMPLE
    .\scripts\win\check.ps1
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-Tool {
    param([Parameter(Mandatory)][string]$Name)
    $venvExe = Join-Path $PSScriptRoot "..\..\.venv\Scripts\$Name.exe"
    if (Test-Path $venvExe) { return (Resolve-Path $venvExe).Path }
    $onPath = Get-Command $Name -ErrorAction SilentlyContinue
    if ($onPath) {
        Write-Warning "$Name not found in .venv; using $($onPath.Source) from PATH instead"
        return $onPath.Source
    }
    throw "'$Name' was not found in .venv\Scripts or on PATH"
}

function Invoke-Step {
    param(
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][string]$Exe,
        [Parameter(Mandatory)][string[]]$Arguments
    )
    Write-Host "==> $Description" -ForegroundColor Cyan
    & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAILED: $Description (exit $LASTEXITCODE)" -ForegroundColor Red
        exit $LASTEXITCODE
    }
}

$ruff = Resolve-Tool 'ruff'
$pytest = Resolve-Tool 'pytest'

Invoke-Step -Description 'ruff format .'      -Exe $ruff -Arguments @('format', '.')
Invoke-Step -Description 'ruff check . --fix' -Exe $ruff -Arguments @('check', '.', '--fix')
Invoke-Step -Description 'ruff check .'       -Exe $ruff -Arguments @('check', '.')
Invoke-Step -Description 'pytest -q'          -Exe $pytest -Arguments @('-q')

Write-Host "`nall checks passed" -ForegroundColor Green
