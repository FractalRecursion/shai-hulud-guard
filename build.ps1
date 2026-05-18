# build.ps1 — thin PowerShell wrapper around build.py
#
# Usage:
#   .\build.ps1               # build both v1.1 and v2.0 .exe
#   .\build.ps1 -V1           # build only v1.1
#   .\build.ps1 -V2           # build only v2.0
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
    [switch]$V1,
    [switch]$V2,
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

$pythonArgs = @("build.py")
if ($V1)    { $pythonArgs += "--v1" }
if ($V2)    { $pythonArgs += "--v2" }
if ($Clean) { $pythonArgs += "--clean" }

Write-Host "[build.ps1] python $($pythonArgs -join ' ')"
& python @pythonArgs
exit $LASTEXITCODE
