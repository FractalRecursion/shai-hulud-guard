#!/usr/bin/env python3
"""
build.py — Cross-platform PyInstaller build for shai_hulud_guard.

Produces single-file binaries (.exe on Windows, no-extension on Linux/macOS)
for BOTH versions of the tool:

  - shai_hulud_guard            ← v2.0 (interactive, recommended)
  - shai_hulud_guard_legacy     ← v1.1 (flag-based, scriptable for CI)

Both end up in ./dist/ alongside ./build/ scratch directories.

Usage:
  python build.py             # build both
  python build.py --v1        # build only v1.1 -> shai_hulud_guard_legacy[.exe]
  python build.py --v2        # build only v2.0 -> shai_hulud_guard[.exe]
  python build.py --clean     # remove build/ dist/ *.spec, then exit

Why we use PyInstaller (and not Nuitka):
  - Single dev dependency, well-known, stable.
  - --onefile produces ONE artifact for users with no Python installed.
  - The runtime cost (a few MB and a brief unpack at start) is acceptable
    for an incident-response tool that runs interactively.

Determinism / reproducibility caveat:
  PyInstaller bundles a copy of the Python interpreter + stdlib. The exact
  bytes therefore depend on the build machine's Python build. For genuinely
  reproducible binaries you would need to pin Python version + PyInstaller
  version + run in a fresh container. We do not do that here — but the
  source .py file IS the canonical artifact; the binary is a convenience.
"""
from __future__ import annotations

import argparse
import platform
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
V1_PATH = ROOT / "shai_hulud_guard.py"
V2_PATH = ROOT / "shai_hulud_guard V2.0.py"

# Output binary basenames (PyInstaller appends .exe on Windows automatically).
V1_NAME = "shai_hulud_guard_legacy"
V2_NAME = "shai_hulud_guard"


def _ensure_pyinstaller() -> None:
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print("[build] PyInstaller is not installed.", file=sys.stderr)
        print('[build] Install with:  pip install -e ".[dev]"', file=sys.stderr)
        print("[build] Or just:        pip install pyinstaller", file=sys.stderr)
        sys.exit(2)


def _platform_tag() -> str:
    sysname = platform.system().lower()      # 'windows' | 'darwin' | 'linux'
    arch    = platform.machine().lower()     # 'amd64' | 'x86_64' | 'arm64' | ...
    arch_norm = {"amd64": "x86_64"}.get(arch, arch)
    return f"{sysname}_{arch_norm}"


def _run_pyinstaller(script: Path, name: str) -> Path:
    """Invoke PyInstaller for `script`, output binary named `name`."""
    if not script.exists():
        print(f"[build] ERROR: source script not found: {script}", file=sys.stderr)
        sys.exit(1)

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--console",
        "--clean",
        "--noconfirm",
        "--name", name,
        # Strip platform-specific output dirs (default is dist/ build/ — kept).
        str(script),
    ]
    print(f"[build] Building {script.name}  ->  dist/{name}{_exe_suffix()}")
    print(f"[build] $ {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=ROOT, check=False)
    if result.returncode != 0:
        print(f"[build] PyInstaller failed with exit code {result.returncode}",
              file=sys.stderr)
        sys.exit(result.returncode)

    out = ROOT / "dist" / f"{name}{_exe_suffix()}"
    if not out.exists():
        print(f"[build] WARNING: expected output not found: {out}", file=sys.stderr)
    return out


def _exe_suffix() -> str:
    return ".exe" if platform.system() == "Windows" else ""


def _clean() -> None:
    for d in ("build", "dist"):
        p = ROOT / d
        if p.exists():
            print(f"[build] rm -rf {p}")
            shutil.rmtree(p, ignore_errors=True)
    for spec in ROOT.glob("*.spec"):
        print(f"[build] rm {spec}")
        spec.unlink()


def main() -> int:
    parser = argparse.ArgumentParser(description="PyInstaller build for shai_hulud_guard")
    g = parser.add_mutually_exclusive_group()
    g.add_argument("--v1",    action="store_true", help="build only v1.1 -> shai_hulud_guard_legacy")
    g.add_argument("--v2",    action="store_true", help="build only v2.0 -> shai_hulud_guard")
    g.add_argument("--clean", action="store_true", help="remove build/ dist/ *.spec and exit")
    args = parser.parse_args()

    if args.clean:
        _clean()
        return 0

    _ensure_pyinstaller()

    print(f"[build] Platform: {_platform_tag()}")
    print(f"[build] Python:   {sys.version.split()[0]}")
    print()

    built: list[Path] = []
    if args.v1 or not args.v2:
        built.append(_run_pyinstaller(V1_PATH, V1_NAME))
    if args.v2 or not args.v1:
        built.append(_run_pyinstaller(V2_PATH, V2_NAME))

    print()
    print("[build] Done. Artifacts:")
    for b in built:
        if b.exists():
            size_mb = b.stat().st_size / (1024 * 1024)
            print(f"[build]   {b}  ({size_mb:.1f} MB)")
        else:
            print(f"[build]   {b}  (NOT FOUND — see PyInstaller output above)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
