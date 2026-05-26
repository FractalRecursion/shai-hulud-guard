#!/usr/bin/env python3
"""
tools/refresh_advisories.py — MAINTAINER-ONLY advisory refresh helper.

This is NOT part of the scanner. The scanner (shai_hulud_guard.py) must never
phone home beyond the npm/PyPI registries (CLAUDE.md §5.4). This tool is the
sanctioned, run-by-a-human way to keep ``KNOWN_BAD[...]["advisories"]`` current,
sourced ONLY from authoritative databases:

    OSV.dev  (https://osv.dev)  — Google's aggregator of GHSA + NVD + the
    npm / PyPI malicious-package feeds. We prefer GHSA IDs (CLAUDE.md §4.7).

Why a separate tool (and not in the scanner):
  - Keeps the shipped scanner stdlib-only and free of any non-registry network
    call — a hard supply-chain-hardening invariant for a security tool.
  - Same precedent as benchmarks/run_calibration.py: dev/maintainer tooling may
    hit the network; the scanner may not.

Usage:
    python tools/refresh_advisories.py          # human-readable suggestions
    python tools/refresh_advisories.py --json    # machine-readable

It queries OSV for every package in KNOWN_BAD (BOTH npm and PyPI, since
KNOWN_BAD is ecosystem-agnostic), keeps only supply-chain / malicious-code
advisories (NOT ordinary CVEs in the same package), and prints the GHSA IDs a
maintainer should review and paste. It NEVER edits source automatically — a
human verifies each ID at https://github.com/advisories first (CLAUDE.md §5.5).
Exit code 1 if any package has a suggested advisory not yet recorded.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OSV_QUERY = "https://api.osv.dev/v1/query"
ECOSYSTEMS = ("npm", "PyPI")
# A vuln counts as supply-chain/malicious if its ID is from a malware feed
# (MAL-*) or its text names a compromise. Ordinary CVEs (e.g. an XXE bug in the
# package) are excluded — KNOWN_BAD tracks the worm campaign, not every CVE.
_MAL_MARKERS = ("malicious", "malware", "compromis", "supply chain",
                "supply-chain", "dropper", "exfiltrat")


def _load_known_bad() -> dict:
    spec = importlib.util.spec_from_file_location("_shg_kb", ROOT / "shai_hulud_guard.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.KNOWN_BAD


def _osv_query(name: str, ecosystem: str) -> list:
    body = json.dumps({"package": {"name": name, "ecosystem": ecosystem}}).encode()
    req = urllib.request.Request(
        OSV_QUERY, data=body,
        headers={"Content-Type": "application/json",
                 "User-Agent": "shai-hulud-guard-advisory-refresh"},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.load(r).get("vulns") or []
    except Exception as e:  # noqa: BLE001 — best-effort maintainer tool
        print(f"  ! OSV query failed for {name} ({ecosystem}): {e}", file=sys.stderr)
        return []


def _is_supply_chain(vuln: dict) -> bool:
    if (vuln.get("id") or "").startswith("MAL-"):
        return True
    text = ((vuln.get("summary") or "") + " " + (vuln.get("details") or "")).lower()
    return any(m in text for m in _MAL_MARKERS)


def _ghsa_ids(vuln: dict) -> list:
    ids = []
    if (vuln.get("id") or "").startswith("GHSA-"):
        ids.append(vuln["id"])
    ids += [a for a in (vuln.get("aliases") or []) if a.startswith("GHSA-")]
    return ids or ([vuln["id"]] if vuln.get("id") else [])


def refresh() -> dict:
    known = _load_known_bad()
    report = {}
    for name, entry in known.items():
        found: set = set()
        for eco in ECOSYSTEMS:
            for v in _osv_query(name, eco):
                if _is_supply_chain(v):
                    found.update(_ghsa_ids(v))
        current = set(entry.get("advisories", []))
        report[name] = {
            "current": sorted(current),
            "suggested": sorted(found),
            "missing": sorted(found - current),
        }
    return report


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Refresh KNOWN_BAD advisories from OSV.dev (maintainer tool, not the scanner)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    report = refresh()
    if args.json:
        print(json.dumps(report, indent=2))
        return 1 if any(r["missing"] for r in report.values()) else 0

    print("KNOWN_BAD advisory refresh  (source: OSV.dev — GHSA / NVD / malware feeds)\n")
    any_missing = False
    for name, r in report.items():
        flag = "   <-- review & add" if r["missing"] else ""
        any_missing = any_missing or bool(r["missing"])
        print(f"  {name}")
        print(f"      current  : {r['current'] or '-'}")
        print(f"      suggested: {r['suggested'] or '-'}{flag}")
    print("\nVerify each suggested GHSA at https://github.com/advisories before pasting"
          "\ninto KNOWN_BAD (CLAUDE.md §5.5). This tool never edits source automatically.")
    return 1 if any_missing else 0


if __name__ == "__main__":
    sys.exit(main())
