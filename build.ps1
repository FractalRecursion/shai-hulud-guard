# build.ps1 — thin PowerShell wrapper around build.py
#
# Usage:
#   .\build.ps1               # build dist/shai_hulud_guard.exe
#   .\build.ps1 -Clean        # remove build/ dist/ *.spec
#
# Prereqs:
#   pip install -e ".[dev]"   # installs PyInstaller (and ruff, pytest)
#
# This file exists so Windows users don't need to remember the exact python
# command. The real logic lives in build.py — keep both files in sync if
# adding flags.

[CmdletBinding()]
param(
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

$pythonArgs = @("build.py")
if ($Clean) { $pythonArgs += "--clean" }

Write-Host "[build.ps1] python $($pythonArgs -join ' ')"
& python @pythonArgs
exit $LASTEXITCODE
