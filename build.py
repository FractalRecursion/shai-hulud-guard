#!/usr/bin/env python3
"""
build.py — Cross-platform PyInstaller build for shai_hulud_guard.

Produces a single-file binary (``shai_hulud_guard[.exe]``) from the canonical
v2.4 single-file CLI ``shai_hulud_guard.py``. The binary lands in ``./dist/``
with ``./build/`` as the scratch directory.

Usage:
  python build.py            # build dist/shai_hulud_guard[.exe]
  python build.py --clean    # remove build/ dist/ *.spec, then exit

The canonical artifact is the source ``shai_hulud_guard.py`` itself (stdlib
only, runs on any Python 3.8+). The binary is a convenience for users who do
not have Python installed.

Why PyInstaller (and not Nuitka):
  - Single dev dependency, well-known, stable.
  - --onefile produces ONE artifact for users with no Python installed.
  - The runtime cost (a few MB and a brief unpack at start) is acceptable
    for an incident-response tool.

Determinism / reproducibility caveat:
  PyInstaller bundles a copy of the Python interpreter + stdlib, so the exact
  bytes depend on the build machine's Python build. The release workflow
  (.github/workflows/release.yml) publishes a SHA-256 checksum (and SLSA
  provenance) for every artifact so users can verify what they downloaded.
  The source .py file remains the canonical artifact; the binary is a
  convenience.
"""
from __future__ import annotations

import argparse
import hashlib
import platform
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
GUARD_PATH = ROOT / "shai_hulud_guard.py"

# Output binary basename (PyInstaller appends .exe on Windows automatically).
GUARD_NAME = "shai_hulud_guard"


def _ensure_pyinstaller() -> None:
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print("[build] PyInstaller is not installed.", file=sys.stderr)
        print('[build] Install with:  pip install -e ".[dev]"', file=sys.stderr)
        print("[build] Or just:        pip install pyinstaller", file=sys.stderr)
        sys.exit(2)


def _exe_suffix() -> str:
    return ".exe" if platform.system() == "Windows" else ""


def _platform_tag() -> str:
    sysname = platform.system().lower()      # 'windows' | 'darwin' | 'linux'
    arch = platform.machine().lower()        # 'amd64' | 'x86_64' | 'arm64' | ...
    arch_norm = {"amd64": "x86_64"}.get(arch, arch)
    return f"{sysname}_{arch_norm}"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


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


def _clean() -> None:
    for d in ("build", "dist"):
        p = ROOT / d
        if p.exists():
            print(f"[build] removing {p}")
            shutil.rmtree(p, ignore_errors=True)
    for spec in ROOT.glob("*.spec"):
        print(f"[build] removing {spec}")
        spec.unlink()


def main() -> int:
    parser = argparse.ArgumentParser(description="PyInstaller build for shai_hulud_guard")
    parser.add_argument("--clean", action="store_true",
                        help="remove build/ dist/ *.spec and exit")
    args = parser.parse_args()

    if args.clean:
        _clean()
        return 0

    _ensure_pyinstaller()

    print(f"[build] Platform: {_platform_tag()}")
    print(f"[build] Python:   {sys.version.split()[0]}")
    print()

    out = _run_pyinstaller(GUARD_PATH, GUARD_NAME)

    print()
    print("[build] Done. Artifact:")
    if out.exists():
        size_mb = out.stat().st_size / (1024 * 1024)
        print(f"[build]   {out}  ({size_mb:.1f} MB)")
        print(f"[build]   sha256: {_sha256(out)}")
    else:
        print(f"[build]   {out}  (NOT FOUND — see PyInstaller output above)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
