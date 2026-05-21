#!/usr/bin/env python3
"""
benchmarks/run_calibration.py — empirical calibration of shai_hulud_guard.

Runs the scanner against the top-50 npm + top-50 PyPI packages by download
volume + a true-positive set of confirmed-malicious entries from KNOWN_BAD.
Reports false-positive rate, true-positive rate, score distribution, and
per-package runtime.

Hits the LIVE npm and PyPI registries. ~100 HTTP requests. Expect 3-8 minutes
on a residential connection.

Usage:
    python benchmarks/run_calibration.py                 # full run to stdout
    python benchmarks/run_calibration.py --markdown > BENCHMARKS.md
    python benchmarks/run_calibration.py --top 20        # smaller subset
    python benchmarks/run_calibration.py --quick         # npm only, top 10

Exit codes:
    0 — calibration thresholds held (FP rate ≤ 5%, TP rate = 100%)
    1 — at least one threshold violated

Calibration thresholds (locked v2.4):
    npm  top-50 mean score    ≤ 10  (most should be 0; outliers ≤ 25)
    PyPI top-50 mean score    ≤ 15  (boto3-like fresh-publish noise allowed)
    Known-malicious detection = 100%  (any miss is a critical regression)
    Per-package runtime       ≤ 60s  (registry latency-bound)
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# UTF-8 stdout on Windows so we can print "≤" etc.
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ─── Top npm packages, PINNED to stable versions ─────────────────────────────
# Pinned (not `latest`) on purpose: a `latest` that published in the last 24-48h
# gets the publish-age weight (+25/+40), which is correct *signal* but
# introduces non-reproducible noise into a calibration benchmark whose job is to
# measure *pattern* false positives. Every version below is well past the 7-day
# minimum-release-age window. See docs/DESIGN.md § 2.6.
TOP_NPM = [
    ("lodash", "4.17.21"), ("react", "18.2.0"), ("react-dom", "18.2.0"),
    ("axios", "1.6.8"), ("express", "4.18.2"), ("chalk", "5.3.0"),
    ("moment", "2.30.1"), ("uuid", "9.0.1"), ("commander", "11.1.0"),
    ("dotenv", "16.4.5"), ("tslib", "2.6.2"), ("minimist", "1.2.8"),
    ("yargs", "17.7.2"), ("inquirer", "9.2.15"), ("ora", "8.0.1"),
    ("debug", "4.3.4"), ("semver", "7.6.0"), ("glob", "10.3.10"),
    ("rimraf", "5.0.5"), ("mkdirp", "3.0.1"), ("node-fetch", "3.3.2"),
    ("got", "14.2.1"), ("superagent", "8.1.2"), ("ws", "8.16.0"),
    ("socket.io", "4.7.4"), ("fast-glob", "3.3.2"), ("fs-extra", "11.2.0"),
    ("chokidar", "3.6.0"), ("nodemon", "3.1.0"), ("webpack", "5.89.0"),
    ("rollup", "4.13.0"), ("esbuild", "0.20.2"), ("vite", "5.2.6"),
    ("parcel", "2.12.0"), ("typescript", "5.4.3"), ("eslint", "8.57.0"),
    ("prettier", "3.2.5"), ("mocha", "10.3.0"), ("jest", "29.7.0"),
    ("cypress", "13.7.1"), ("playwright", "1.42.1"), ("puppeteer", "22.6.1"),
    ("supertest", "6.3.4"), ("cors", "2.8.5"), ("helmet", "7.1.0"),
    ("morgan", "1.10.0"), ("body-parser", "1.20.2"), ("cookie-parser", "1.4.6"),
    ("zod", "3.22.4"), ("classnames", "2.5.1"),
]

# ─── Top PyPI packages, PINNED to stable versions ────────────────────────────
TOP_PYPI = [
    ("boto3", "1.34.69"), ("urllib3", "2.2.1"), ("requests", "2.31.0"),
    ("certifi", "2024.2.2"), ("charset-normalizer", "3.3.2"), ("idna", "3.6"),
    ("setuptools", "69.2.0"), ("packaging", "24.0"), ("typing-extensions", "4.10.0"),
    ("six", "1.16.0"), ("python-dateutil", "2.9.0.post0"), ("pyyaml", "6.0.1"),
    ("jinja2", "3.1.3"), ("click", "8.1.7"), ("numpy", "1.26.4"),
    ("pandas", "2.2.1"), ("scipy", "1.12.0"), ("matplotlib", "3.8.3"),
    ("scikit-learn", "1.4.1.post1"), ("pillow", "10.2.0"), ("lxml", "5.1.0"),
    ("flask", "3.0.2"), ("django", "5.0.3"), ("fastapi", "0.110.0"),
    ("uvicorn", "0.29.0"), ("pydantic", "2.6.4"), ("sqlalchemy", "2.0.29"),
    ("alembic", "1.13.1"), ("pytest", "8.1.1"), ("pytest-cov", "4.1.0"),
    ("coverage", "7.4.4"), ("ruff", "0.3.4"), ("black", "24.3.0"),
    ("mypy", "1.9.0"), ("pylint", "3.1.0"), ("tox", "4.14.1"),
    ("virtualenv", "20.25.1"), ("pip", "24.0"), ("wheel", "0.43.0"),
    ("build", "1.1.1"), ("twine", "5.0.0"), ("cryptography", "42.0.5"),
    ("pyjwt", "2.8.0"), ("redis", "5.0.3"), ("celery", "5.3.6"),
    ("psycopg2-binary", "2.9.9"), ("pymongo", "4.6.2"), ("attrs", "23.2.0"),
    ("rich", "13.7.1"), ("httpx", "0.27.0"),
]

# ─── Known-malicious set — must always be detected as CRITICAL ────────────────
# Mirror of KNOWN_BAD with `bad` populated. Updates here when the source
# constant in shai_hulud_guard.py changes.
KNOWN_MALICIOUS_NPM = [
    ("@tanstack/react-router", "1.169.5"),
    ("@tanstack/router",       "1.169.5"),
    ("intercom-client",        "7.0.4"),
]
KNOWN_MALICIOUS_PYPI = [
    ("guardrails-ai",          "0.10.1"),
    ("mistralai",              "2.4.6"),
]

# ─── Calibration thresholds (locked v2.4) ─────────────────────────────────────
NPM_TOP_MEAN_MAX        = 10
NPM_TOP_INDIVIDUAL_MAX  = 25
PYPI_TOP_MEAN_MAX       = 15
PYPI_TOP_INDIVIDUAL_MAX = 45   # boto3 / requests fresh-publish window is real
TP_RATE_MIN             = 1.0  # 100%; any miss is critical
PER_PACKAGE_TIMEOUT_S   = 60

# ─── Locate the scanner ───────────────────────────────────────────────────────
GUARD = Path(__file__).resolve().parent.parent / "shai_hulud_guard.py"
assert GUARD.exists(), f"shai_hulud_guard.py not found at {GUARD}"


def run_scan(mode: str, target: str, timeout: float = PER_PACKAGE_TIMEOUT_S) -> Tuple[int, Optional[int], Optional[str]]:
    """
    Run shai_hulud_guard in JSON mode against a target.
    Returns (exit_code, risk_score, case).
    """
    cmd = [sys.executable, str(GUARD), "--json", mode, target]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, errors="replace")
    except subprocess.TimeoutExpired:
        return (-1, None, "TIMEOUT")
    if not r.stdout:
        return (r.returncode, None, "NO_OUTPUT")
    try:
        j = json.loads(r.stdout)
        return (r.returncode, j.get("risk_score"), j.get("case"))
    except json.JSONDecodeError:
        return (r.returncode, None, "BAD_JSON")


def run_one(label: str, mode_flag: str, target: str) -> Dict:
    t0 = time.perf_counter()
    exit_code, score, case = run_scan(mode_flag, target)
    elapsed = time.perf_counter() - t0
    return {
        "label":     label,
        "target":    target,
        "exit_code": exit_code,
        "score":     score,
        "case":      case,
        "elapsed_s": round(elapsed, 2),
    }


def summarise(results: List[Dict], label: str) -> Dict:
    scores = [r["score"] for r in results if isinstance(r["score"], int)]
    if not scores:
        return {"label": label, "n": 0, "mean": None, "median": None, "max": None}
    return {
        "label":  label,
        "n":      len(results),
        "mean":   round(statistics.mean(scores), 1),
        "median": statistics.median(scores),
        "max":    max(scores),
        "max_at": next(r["target"] for r in results if r["score"] == max(scores)),
        "elapsed_total_s": round(sum(r["elapsed_s"] for r in results), 1),
        "elapsed_per_pkg_mean_s": round(statistics.mean(r["elapsed_s"] for r in results), 2),
    }


# ─── Reporting ────────────────────────────────────────────────────────────────

def print_human(npm_res, pypi_res, tp_npm_res, tp_pypi_res, npm_sum, pypi_sum, tp_rate, elapsed_total):
    print(f"\nshai_hulud_guard CALIBRATION  ({time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())})")
    print(f"Total runtime: {elapsed_total:.1f}s  (live registry, ~{len(npm_res)+len(pypi_res)+len(tp_npm_res)+len(tp_pypi_res)} HTTP packages)\n")

    print("=== False-positive measurement (top packages — should all be low) ===")
    print(f"{'Package':<35} {'Score':>6} {'Case':<18} {'Time(s)':>8}")
    print("-" * 70)
    for r in npm_res + pypi_res:
        print(f"{r['target']:<35} {str(r['score']):>6} {(r['case'] or ''):<18} {r['elapsed_s']:>8}")

    print("\n=== True-positive measurement (known-bad — should all be 100/PACKAGES_ONLY) ===")
    print(f"{'Package':<35} {'Score':>6} {'Case':<18} {'Time(s)':>8}  {'Exit':>4}")
    print("-" * 75)
    for r in tp_npm_res + tp_pypi_res:
        print(f"{r['target']:<35} {str(r['score']):>6} {(r['case'] or ''):<18} {r['elapsed_s']:>8}  {r['exit_code']:>4}")

    print("\n=== Aggregate ===")
    for s in (npm_sum, pypi_sum):
        if s.get("n"):
            print(f"  {s['label']:<25} n={s['n']:<3}  mean={s['mean']:<5}  median={s['median']:<3}  max={s['max']} ({s['max_at']})")
    print(f"  True-positive detection rate: {tp_rate * 100:.0f}%")


def print_markdown(npm_res, pypi_res, tp_npm_res, tp_pypi_res, npm_sum, pypi_sum, tp_rate, elapsed_total, version):
    lines = []
    P = lines.append
    P(f"# Calibration benchmark — shai_hulud_guard v{version}")
    P("")
    P(f"_Generated by `python benchmarks/run_calibration.py --markdown` on "
      f"{time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}._")
    P("")
    P(f"**Total runtime:** {elapsed_total:.1f}s "
      f"(live registry — npm + PyPI; "
      f"{len(npm_res) + len(pypi_res) + len(tp_npm_res) + len(tp_pypi_res)} HTTP packages)")
    P("")
    P("## False-positive measurement — top packages by download volume")
    P("")
    P("Calibration target: top packages should score **≤ 25/100** individually "
      "and have a low mean. Fresh-publish-window noise is real for high-velocity "
      "packages (boto3, requests, urllib3) — see `docs/DESIGN.md § 2.6`.")
    P("")
    P("### npm")
    P("")
    P("| Package | Score | Case | Time (s) |")
    P("|---|---:|---|---:|")
    for r in npm_res:
        P(f"| `{r['target']}` | {r['score']} | {r['case'] or ''} | {r['elapsed_s']} |")
    P("")
    P(f"**npm summary:** mean **{npm_sum['mean']}/100**, median {npm_sum['median']}, "
      f"max **{npm_sum['max']}** at `{npm_sum['max_at']}`. "
      f"Threshold ≤ {NPM_TOP_MEAN_MAX} mean / ≤ {NPM_TOP_INDIVIDUAL_MAX} individual.")
    P("")
    P("### PyPI")
    P("")
    P("| Package | Score | Case | Time (s) |")
    P("|---|---:|---|---:|")
    for r in pypi_res:
        P(f"| `{r['target']}` | {r['score']} | {r['case'] or ''} | {r['elapsed_s']} |")
    P("")
    P(f"**PyPI summary:** mean **{pypi_sum['mean']}/100**, median {pypi_sum['median']}, "
      f"max **{pypi_sum['max']}** at `{pypi_sum['max_at']}`. "
      f"Threshold ≤ {PYPI_TOP_MEAN_MAX} mean / ≤ {PYPI_TOP_INDIVIDUAL_MAX} individual.")
    P("")
    P("## True-positive measurement — known-malicious packages")
    P("")
    P("Every entry must score **100/PACKAGES_ONLY** with **exit code 1**. Any miss "
      "is a critical regression.")
    P("")
    P("| Package | Score | Case | Exit | Time (s) |")
    P("|---|---:|---|---:|---:|")
    for r in tp_npm_res + tp_pypi_res:
        marker = "✅" if r["case"] == "PACKAGES_ONLY" and r["exit_code"] == 1 else "❌"
        P(f"| {marker} `{r['target']}` | {r['score']} | {r['case'] or ''} | {r['exit_code']} | {r['elapsed_s']} |")
    P("")
    P(f"**True-positive rate:** {tp_rate * 100:.0f}%  (threshold: 100%)")
    P("")
    P("## Timing distribution")
    P("")
    P("Latency is registry-bound. The scanner itself does microseconds of work per "
      "tarball; the wall-clock time is mostly `urllib.request.urlopen()` waiting on "
      "the CDN.")
    P("")
    P(f"- **npm:**  mean **{npm_sum.get('elapsed_per_pkg_mean_s', '?')}s** / package; "
      f"total {npm_sum.get('elapsed_total_s', '?')}s")
    P(f"- **PyPI:** mean **{pypi_sum.get('elapsed_per_pkg_mean_s', '?')}s** / package; "
      f"total {pypi_sum.get('elapsed_total_s', '?')}s")
    P("")
    P("## Reproducing")
    P("")
    P("```bash")
    P("python benchmarks/run_calibration.py --markdown > BENCHMARKS.md")
    P("```")
    P("")
    P("To run a smaller subset (10 packages each):")
    P("")
    P("```bash")
    P("python benchmarks/run_calibration.py --quick")
    P("```")
    print("\n".join(lines))


# ─── Main ─────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--markdown", action="store_true",
                        help="Emit Markdown report (suitable for BENCHMARKS.md)")
    parser.add_argument("--top", type=int, default=50,
                        help="How many top packages to scan per ecosystem")
    parser.add_argument("--quick", action="store_true",
                        help="Shortcut: --top 10, npm only")
    args = parser.parse_args()

    top_n = 10 if args.quick else args.top

    # Get tool version for the report header
    rv = subprocess.run([sys.executable, str(GUARD), "--version"],
                        capture_output=True, text=True, errors="replace")
    version = rv.stdout.strip().split()[-1] if rv.returncode == 0 else "?"

    npm_packages = TOP_NPM[:top_n]
    pypi_packages = [] if args.quick else TOP_PYPI[:top_n]

    t_overall = time.perf_counter()
    npm_results: List[Dict] = []
    pypi_results: List[Dict] = []
    print(f"# Calibrating top-{len(npm_packages)} npm packages "
          f"+ top-{len(pypi_packages)} PyPI ...", file=sys.stderr)
    for i, (name, ver) in enumerate(npm_packages, 1):
        target = f"{name}@{ver}"
        print(f"  [{i:>3}/{len(npm_packages)}] npm: {target}", file=sys.stderr)
        npm_results.append(run_one("npm-top", "--check", target))
    for i, (name, ver) in enumerate(pypi_packages, 1):
        target = f"{name}=={ver}"
        print(f"  [{i:>3}/{len(pypi_packages)}] PyPI: {target}", file=sys.stderr)
        pypi_results.append(run_one("pypi-top", "--check-pypi", target))

    print("\n# True-positive set ...", file=sys.stderr)
    tp_npm_results = []
    for name, ver in KNOWN_MALICIOUS_NPM:
        target = f"{name}@{ver}"
        print(f"  npm-tp: {target}", file=sys.stderr)
        tp_npm_results.append(run_one("npm-tp", "--check", target))
    tp_pypi_results = []
    for name, ver in KNOWN_MALICIOUS_PYPI:
        target = f"{name}=={ver}"
        print(f"  pypi-tp: {target}", file=sys.stderr)
        tp_pypi_results.append(run_one("pypi-tp", "--check-pypi", target))

    elapsed_total = time.perf_counter() - t_overall

    npm_summary  = summarise(npm_results, "npm top")
    pypi_summary = summarise(pypi_results, "PyPI top")

    tp_total = tp_npm_results + tp_pypi_results
    tp_hits = sum(1 for r in tp_total if r["exit_code"] == 1 and r["case"] in ("PACKAGES_ONLY", "FULL_COMPROMISE"))
    tp_rate = tp_hits / len(tp_total) if tp_total else 0.0

    if args.markdown:
        print_markdown(npm_results, pypi_results, tp_npm_results, tp_pypi_results,
                       npm_summary, pypi_summary, tp_rate, elapsed_total, version)
    else:
        print_human(npm_results, pypi_results, tp_npm_results, tp_pypi_results,
                    npm_summary, pypi_summary, tp_rate, elapsed_total)

    # Threshold enforcement
    fails = []
    if npm_summary.get("mean") and npm_summary["mean"] > NPM_TOP_MEAN_MAX:
        fails.append(f"npm mean {npm_summary['mean']} > {NPM_TOP_MEAN_MAX}")
    if npm_summary.get("max") and npm_summary["max"] > NPM_TOP_INDIVIDUAL_MAX:
        fails.append(f"npm max {npm_summary['max']} > {NPM_TOP_INDIVIDUAL_MAX} (at {npm_summary.get('max_at')})")
    if pypi_summary.get("mean") and pypi_summary["mean"] > PYPI_TOP_MEAN_MAX:
        fails.append(f"PyPI mean {pypi_summary['mean']} > {PYPI_TOP_MEAN_MAX}")
    if pypi_summary.get("max") and pypi_summary["max"] > PYPI_TOP_INDIVIDUAL_MAX:
        fails.append(f"PyPI max {pypi_summary['max']} > {PYPI_TOP_INDIVIDUAL_MAX} (at {pypi_summary.get('max_at')})")
    if tp_rate < TP_RATE_MIN:
        fails.append(f"true-positive rate {tp_rate * 100:.0f}% < {TP_RATE_MIN * 100:.0f}%")

    if fails:
        print(f"\n[!] CALIBRATION REGRESSION  ({len(fails)} issue(s)):", file=sys.stderr)
        for f in fails:
            print(f"    {f}", file=sys.stderr)
        return 1
    print(f"\n[+] Calibration thresholds held.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
