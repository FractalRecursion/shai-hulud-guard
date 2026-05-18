#!/usr/bin/env python3
"""
shai_hulud_guard.py  v1.1.0
───────────────────────────────────────────────────────────────────────────────
Cross-platform scanner for the Shai-Hulud npm supply-chain worm family.
Covers all documented waves (Sept 2025 → May 2026) and the Mini variant.

MODES
─────
  --scan     Detect infection indicators in an existing project / machine
  --check    Pre-install safety analysis of a specific npm (or PyPI) package
  --incident Print step-by-step incident response guide

USAGE
─────
  python shai_hulud_guard.py --scan
  python shai_hulud_guard.py --scan --path /path/to/project
  python shai_hulud_guard.py --check @tanstack/react-router
  python shai_hulud_guard.py --check @tanstack/react-router@1.169.5
  python shai_hulud_guard.py --incident

HONEST LIMITATIONS
──────────────────
  • Pattern detection can be evaded by novel obfuscation
  • Known-bad version list lags active attacks (always cross-check Datadog IOC repo)
  • 'No findings' is not a guarantee of clean state
  • Does NOT replace behavioral analysis at the registry/network layer (Socket, Wiz, Snyk)
  • Tarball scan is heuristic — a zero-day variant will produce zero findings

Requirements: Python 3.8+ — zero external dependencies
"""

import argparse
import base64
import hashlib
import io
import json
import os
import platform
import re
import sys
import tarfile
import textwrap
import time
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ═══════════════════════════════════════════════════════════════════════════════
#  VERSION & CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

VERSION      = "1.1.0"
REGISTRY_BASE = "https://registry.npmjs.org"
IOC_REPO      = "https://github.com/DataDog/indicators-of-compromise/tree/main/shai-hulud-2.0"
STEPSEC_BLOG  = "https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised"
CISA_ALERT    = "https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem"

# ── Known malicious filenames (payload files deposited by the worm) ──────────
MALICIOUS_FILENAMES = {
    "router_init.js",      # Core payload, all waves (~2.3 MB obfuscated)
    "setup_bun.js",        # Bun installer stub, waves 2+
    "bun_environment.js",  # Bun environment setup, wave 2
    "setup.mjs",           # ESM variant used in wave 1
}

# ── IOC patterns ─────────────────────────────────────────────────────────────
#  Format: (regex, human description, risk_level)
#  risk_level: CRITICAL | HIGH | MEDIUM | LOW
MALICIOUS_PATTERNS: List[Tuple[str, str, str]] = [
    # ── Worm identity markers ────────────────────────────────────────────────
    (r"Sha[i1].?Hulud|Shai.?Hulud",              "Worm identity string",                       "CRITICAL"),
    (r"Here We Go Again|The Second Coming",       "Worm campaign tag",                          "CRITICAL"),
    (r"TeamPCP|DeadCatx3|PCPcat|ShellForce|CipherForce", "Known threat actor marker",          "CRITICAL"),
    (r"gh.?token.?monitor",                       "Persistent token-monitor daemon name",       "CRITICAL"),
    (r"A Mini Shai.?Hulud has Appeared",          "Worm repo description tag",                  "CRITICAL"),

    # ── Destructive payload ──────────────────────────────────────────────────
    (r"rm\s+-rf\s+[\"']?[~$]|rm\s+-rf\s+\$HOME",  "Linux/macOS home-directory wipe",           "CRITICAL"),
    (r"Remove-Item\s+.*-Recurse.*Home|rmdir\s+/s\s+/q\s+.*%USERPROFILE%",
                                                   "Windows home-directory wipe",               "CRITICAL"),

    # ── Exfiltration infrastructure ──────────────────────────────────────────
    (r"git-tanstack\[?\.\]?com|git-tanstack\.com", "Known C2 typosquat domain",                 "CRITICAL"),
    (r"webhook\.site\/[a-f0-9\-]{36}",            "Known exfiltration endpoint (webhook.site)", "CRITICAL"),
    (r"getsession\.org|signal\.org|oxen\.io",     "Session network (C2 exfiltration channel)",  "HIGH"),

    # ── Credential file targeting ────────────────────────────────────────────
    (r"application_default_credentials\.json",    "GCP credential file access",                 "HIGH"),
    (r"\.aws[/\\]credentials|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID",
                                                   "AWS credential access",                     "HIGH"),
    (r"AZURE_CLIENT_SECRET|AZURE_TENANT_ID|azure_credentials",
                                                   "Azure credential access",                   "HIGH"),
    (r"id_rsa|id_ed25519|id_ecdsa",               "SSH private key access",                     "HIGH"),
    (r"\.npmrc",                                   ".npmrc credential file access",              "MEDIUM"),

    # ── Token literal patterns ────────────────────────────────────────────────
    (r"ghp_[A-Za-z0-9]{36}",                      "GitHub PAT literal in code",                 "CRITICAL"),
    (r"gho_[A-Za-z0-9]{36}",                      "GitHub OAuth token literal",                 "CRITICAL"),
    (r"npm_[A-Za-z0-9]{36}",                      "npm token literal",                          "CRITICAL"),

    # ── Runtime substitution (Bun installed silently during preinstall) ──────
    (r"bun\.sh/install|curl.*bun\.sh|install.*bun\.sh|bunx\b",
                                                   "Bun runtime installer in lifecycle script",  "HIGH"),
    (r"\"bun\"\s*,?\s*\"run\"|spawn.*bun\b",      "Bun used to execute payload",                "HIGH"),

    # ── OIDC / CI token extraction ────────────────────────────────────────────
    (r"/proc/\d+/mem|ptrace|process_vm_readv",    "CI runner memory extraction",                "CRITICAL"),
    (r"ACTIONS_ID_TOKEN_REQUEST_URL|ACTIONS_ID_TOKEN_REQUEST_TOKEN",
                                                   "GitHub OIDC token ENV var access",          "HIGH"),
    (r"id.token.*write|id.token.*permissions",    "OIDC id-token scope in config",              "MEDIUM"),

    # ── Persistence installation ──────────────────────────────────────────────
    (r"LaunchAgents.*com\.user\.",                 "macOS LaunchAgent persistence",              "CRITICAL"),
    (r"systemd/user.*\.service",                  "Linux systemd user service persistence",     "CRITICAL"),
    (r"SCHTASKS|schtasks\.exe",                   "Windows Task Scheduler persistence",         "HIGH"),

    # ── Obfuscation signals ───────────────────────────────────────────────────
    (r"atob\s*\(|Buffer\.from\([^,]+,\s*['\"]base64['\"]",
                                                   "Base64 decode pattern (obfuscation signal)",  "MEDIUM"),
    (r"eval\s*\(\s*(atob|Buffer|decodeURI)",       "eval of decoded content",                    "HIGH"),
    # Only flag unicode escapes for ASCII-range characters (0020–007F) —
    # these encode printable ASCII letters/symbols to hide meaning.
    # This avoids false-positives on legitimate i18n libraries (lodash, etc.)
    # that use \u01xx–\uFFxx for actual Unicode character tables.
    (r"(?:\\u00[2-7][0-9a-fA-F]){4,}",
                                                   "ASCII chars encoded as \\u escapes (obfuscation)",  "MEDIUM"),

    # ── GitHub API abuse ──────────────────────────────────────────────────────
    (r"api\.github\.com/user/repos",              "GitHub API repo creation (credential dump)",  "HIGH"),
    (r"github\.com/.*repos.*POST|Authorization.*token",
                                                   "Authenticated GitHub API call in script",    "MEDIUM"),

    # ── Cache poisoning fingerprints ──────────────────────────────────────────
    (r"pull_request_target",                      "pull_request_target trigger (cache poison vector)", "MEDIUM"),
    (r"actions/cache.*restore-keys",              "Cache restore with broad key (potential poison)", "LOW"),
]

# ── Known compromised versions (confirmed from public post-mortems) ──────────
#  Kept deliberately minimal and sourced — the IOC repo is authoritative.
#  name → {"bad": [...], "waves": [...]}
KNOWN_BAD: Dict[str, dict] = {
    "@tanstack/react-router":  {"bad": ["1.169.5"], "waves": ["Wave5-May2026"]},
    "@tanstack/router":        {"bad": ["1.169.5"], "waves": ["Wave5-May2026"]},
    "@tanstack/react-query":   {"bad": [],           "waves": ["Wave5-May2026"]},  # flag for scrutiny
    "@mistralai/mistralai":    {"bad": [],           "waves": ["Wave5-May2026"]},  # PyPI: 2.4.6
    "@uipath/apollo-core":     {"bad": [],           "waves": ["Wave5-May2026"]},
    "guardrails-ai":           {"bad": ["0.10.1"],   "waves": ["Wave5-May2026"]},  # PyPI
    "mistralai":               {"bad": ["2.4.6"],    "waves": ["Wave5-May2026"]},  # PyPI package name
    "@bitwarden/cli":          {"bad": [],           "waves": ["Wave4-Apr2026"]},
    "intercom-client":         {"bad": ["7.0.4"],    "waves": ["Wave5-May2026"]},
    "tinycolor2":              {"bad": [],           "waves": ["Wave1-Sep2025"]},
    "@asyncapi/cli":           {"bad": [],           "waves": ["Wave2-Nov2025"]},
}

# Packages targeted across multiple waves — heightened scrutiny even on safe versions
HIGH_VALUE_TARGETS = set(KNOWN_BAD.keys()) | {
    "@tanstack/form", "@tanstack/table", "@tanstack/virtual",
    "@tanstack/store", "@tanstack/start", "@tanstack/query-core",
    "@squawk/core", "@opensearch-project/opensearch",
}

# Daemon files installed for worm persistence
DAEMON_PATHS = {
    "linux": [
        Path.home() / ".config" / "systemd" / "user" / "gh-token-monitor.service",
    ],
    "darwin": [
        Path.home() / "Library" / "LaunchAgents" / "com.user.gh-token-monitor.plist",
    ],
    "windows": [],  # Windows variant not publicly documented — check Task Scheduler manually
}

# Credential files the worm is documented to sweep
CREDENTIAL_FILES = [
    Path.home() / ".npmrc",
    Path.home() / ".gitconfig",
    Path.home() / ".config" / "gcloud" / "application_default_credentials.json",
    Path.home() / ".aws" / "credentials",
    Path.home() / ".ssh" / "id_rsa",
    Path.home() / ".ssh" / "id_ed25519",
    Path.home() / ".ssh" / "id_ecdsa",
]

# ═══════════════════════════════════════════════════════════════════════════════
#  TERMINAL OUTPUT HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

_USE_COLOR = sys.stdout.isatty() and (
    platform.system() != "Windows" or os.environ.get("FORCE_COLOR") or os.environ.get("TERM")
)

def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text

def ok(msg: str):    print(_c(f"  ✓  {msg}", "32"))
def warn(msg: str):  print(_c(f"  ⚠  {msg}", "33"))
def crit(msg: str):  print(_c(f"  ✗  {msg}", "31;1"))
def info(msg: str):  print(_c(f"  →  {msg}", "36"))
def head(msg: str):  print(_c(f"\n{'═'*62}\n  {msg}\n{'═'*62}", "1"))
def subh(msg: str):  print(_c(f"\n  ┌─ {msg}", "1"))
def dim(msg: str):   print(_c(f"     {msg}", "2"))

# ═══════════════════════════════════════════════════════════════════════════════
#  NETWORK HELPERS  (stdlib only — no requests, no httpx)
# ═══════════════════════════════════════════════════════════════════════════════

_UA = f"shai-hulud-guard/{VERSION} Python/{sys.version_info.major}.{sys.version_info.minor}"

def fetch_json(url: str, timeout: int = 12) -> Optional[dict]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return json.loads(raw.decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        warn(f"HTTP {e.code} fetching {url}")
        return None
    except Exception as e:
        warn(f"Network error fetching {url}: {e}")
        return None

def fetch_bytes(url: str, timeout: int = 45) -> Optional[bytes]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _UA})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except Exception as e:
        warn(f"Download failed ({url}): {e}")
        return None

# ═══════════════════════════════════════════════════════════════════════════════
#  PATTERN ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

def scan_text(text: str) -> List[Tuple[str, str, str]]:
    """
    Run MALICIOUS_PATTERNS against a block of text.
    Returns list of (description, risk_level, matched_snippet).
    Deduplicates by (desc, risk) to avoid flooding on dense payloads.
    """
    seen = set()
    findings = []
    for pattern, desc, risk in MALICIOUS_PATTERNS:
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            key = (desc, risk)
            if key not in seen:
                seen.add(key)
                snippet = m.group(0)[:100]
                findings.append((desc, risk, snippet))
    return findings

def scan_tarball_bytes(tarball_bytes: bytes) -> List[Tuple[str, str, str, str]]:
    """
    Extract a .tgz from bytes (no disk write) and scan all text files.
    Returns list of (filepath_in_tarball, description, risk_level, snippet).
    """
    findings = []
    text_extensions = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".json",
                       ".sh", ".bash", ".py", ".yml", ".yaml", ".env"}
    try:
        with tarfile.open(fileobj=io.BytesIO(tarball_bytes), mode="r:gz") as tf:
            for member in tf.getmembers():
                if not member.isfile():
                    continue
                basename = Path(member.name).name
                # Flag known malicious filenames (regardless of content)
                if basename in MALICIOUS_FILENAMES:
                    findings.append((
                        member.name,
                        f"Known Shai-Hulud payload filename: {basename}",
                        "CRITICAL",
                        basename,
                    ))
                # Scan text-like files for pattern matches
                suffix = Path(member.name).suffix.lower()
                if suffix in text_extensions:
                    try:
                        fobj = tf.extractfile(member)
                        if fobj:
                            content = fobj.read().decode("utf-8", errors="replace")
                            for desc, risk, snippet in scan_text(content):
                                findings.append((member.name, desc, risk, snippet))
                    except Exception:
                        pass
    except Exception as e:
        warn(f"Could not read tarball: {e}")
    return findings

# ═══════════════════════════════════════════════════════════════════════════════
#  MODE 1 — SCAN  (infection detection in an existing project / machine)
# ═══════════════════════════════════════════════════════════════════════════════

def run_scan(project_path: Path) -> int:
    """
    Scan project for Shai-Hulud infection indicators.
    Returns total number of findings (0 = clean by heuristics).
    """
    head("SHAI-HULUD INFECTION SCANNER")
    info(f"Project : {project_path.resolve()}")
    info(f"System  : {platform.system()} {platform.release()} ({platform.machine()})")
    info(f"Python  : {platform.python_version()}")
    info(f"Scan at : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")

    total = 0

    # ── CHECK 1: Persistence daemon ──────────────────────────────────────────
    subh("CHECK 1/6  Persistence daemon  (definitive compromise indicator)")
    plat = platform.system().lower()
    daemon_paths = DAEMON_PATHS.get(plat, [])
    daemon_found = False
    for dp in daemon_paths:
        if dp.exists():
            crit(f"DAEMON FOUND: {dp}")
            crit("This is definitive evidence of active Shai-Hulud infection.")
            crit("⚑  DO NOT revoke tokens yet — isolate the machine first!")
            crit("    Revoking a token triggers 'rm -rf ~/' within 60 seconds.")
            daemon_found = True
            total += 1
    if not daemon_found:
        if plat in ("linux", "darwin"):
            ok("No persistence daemon found at known paths")
        else:
            info("Windows: inspect Task Scheduler manually for 'gh-token-monitor' entries")

    # ── CHECK 2: package.json — known compromised versions ───────────────────
    subh("CHECK 2/6  package.json  (known compromised versions & dependency hygiene)")
    pkg_json_path = project_path / "package.json"
    if not pkg_json_path.exists():
        warn(f"No package.json found at {pkg_json_path}")
        dim("Pass --path to point to your project root")
    else:
        try:
            pkg = json.loads(pkg_json_path.read_text(encoding="utf-8", errors="replace"))
            all_deps: Dict[str, str] = {}
            for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                all_deps.update(pkg.get(section, {}))

            info(f"Found {len(all_deps)} total dependencies")
            bad_count = 0
            git_dep_count = 0

            for dep, ver_spec in all_deps.items():
                # Known-bad version check
                if dep in KNOWN_BAD:
                    known = KNOWN_BAD[dep]
                    # Clean semver operators for exact match
                    clean = re.sub(r"[^0-9.]", "", ver_spec)
                    if known["bad"] and clean in known["bad"]:
                        crit(f"CONFIRMED COMPROMISED: {dep}@{clean}  (waves: {', '.join(known['waves'])})")
                        total += 1
                        bad_count += 1
                    elif dep in HIGH_VALUE_TARGETS:
                        warn(f"High-value target (repeatedly attacked): {dep}@{ver_spec}")
                        warn(f"   Waves: {', '.join(known.get('waves', ['unknown']))}")

                # Git / non-registry dependency (execute prepare hooks on install)
                if any(ver_spec.startswith(p) for p in ("git", "github:", "bitbucket:", "gitlab:", "file:")):
                    warn(f"Non-registry dependency (runs prepare hooks): {dep}: {ver_spec}")
                    git_dep_count += 1
                    total += 1

            if bad_count == 0:
                ok(f"No known-compromised versions in {len(all_deps)} dependencies")
            if git_dep_count == 0:
                ok("All dependencies reference the npm registry")
            dim(f"Known-bad list may lag active attacks → cross-check: {IOC_REPO}")

        except Exception as e:
            warn(f"Could not parse package.json: {e}")

    # ── CHECK 3: Lock file ────────────────────────────────────────────────────
    subh("CHECK 3/6  Lock file & install hygiene")
    lockfiles = {
        "package-lock.json": "npm ci",
        "yarn.lock":         "yarn install --frozen-lockfile",
        "pnpm-lock.yaml":    "pnpm install --frozen-lockfile",
    }
    found_locks = [name for name in lockfiles if (project_path / name).exists()]
    if found_locks:
        ok(f"Lock file(s) present: {', '.join(found_locks)}")
        for lf in found_locks:
            info(f"  Use '{lockfiles[lf]}' in CI — never 'npm install' (ignores lock)")
    else:
        warn("No lock file found — dependency versions are not pinned")
        warn("  Run: npm install  (once, to generate package-lock.json)")
        total += 1

    # Check for .npmrc min-release-age setting
    npmrc = project_path / ".npmrc"
    if npmrc.exists():
        content = npmrc.read_text(encoding="utf-8", errors="replace")
        if "min-release-age" in content:
            ok(".npmrc has min-release-age set")
        else:
            info(".npmrc found but missing 'min-release-age=7d'  (recommended)")
    else:
        info("No .npmrc — consider adding: min-release-age=7d")

    # ── CHECK 4: node_modules deep scan ──────────────────────────────────────
    subh("CHECK 4/6  node_modules  (malicious files & lifecycle hook patterns)")
    nm_path = project_path / "node_modules"
    if not nm_path.exists():
        info("node_modules not present — run 'npm ci --ignore-scripts' first, then re-scan")
    else:
        scanned = 0
        nm_findings = 0
        # Walk all installed packages including scoped (@org/name)
        pkg_dirs: List[Path] = []
        for entry in nm_path.iterdir():
            if entry.name.startswith("@") and entry.is_dir():
                pkg_dirs.extend(e for e in entry.iterdir() if e.is_dir())
            elif entry.is_dir() and not entry.name.startswith("."):
                pkg_dirs.append(entry)

        for pdir in pkg_dirs:
            scanned += 1
            # Check for malicious payload filenames
            for fname in MALICIOUS_FILENAMES:
                fpath = pdir / fname
                if fpath.exists():
                    crit(f"PAYLOAD FILE: {fpath}")
                    nm_findings += 1
                    total += 1

            # Inspect package.json lifecycle scripts
            meta_path = pdir / "package.json"
            if meta_path.exists():
                try:
                    meta = json.loads(meta_path.read_text(encoding="utf-8", errors="replace"))
                    scripts = meta.get("scripts", {})
                    pkg_full_name = meta.get("name", pdir.name)
                    for hook in ("preinstall", "install", "postinstall", "prepare"):
                        if hook in scripts:
                            script_val = scripts[hook]
                            hits = scan_text(script_val)
                            if hits:
                                for desc, risk, snippet in hits:
                                    fn = crit if risk == "CRITICAL" else warn
                                    fn(f"{risk} [{hook}] in {pkg_full_name}: {desc}")
                                    dim(f"Script: {script_val[:120]}")
                                    nm_findings += 1
                                    total += 1
                except Exception:
                    pass

        ok(f"Scanned {scanned} installed packages")
        if nm_findings == 0:
            ok("No malicious indicators in node_modules")

    # ── CHECK 5: Credential exposure ──────────────────────────────────────────
    subh("CHECK 5/6  Credential file presence  (targeted by worm)")
    exposed = [f for f in CREDENTIAL_FILES if f.exists()]
    if exposed:
        warn(f"{len(exposed)} credential file(s) on disk — targeted by worm's credential sweep:")
        for f in exposed:
            dim(str(f))
        info("If infection is suspected → rotate ALL credentials before reconnecting")
    else:
        ok("No credential files found at standard paths")

    # ── CHECK 6: GitHub Actions workflow audit ────────────────────────────────
    subh("CHECK 6/6  GitHub Actions workflows  (CI/CD attack surface)")
    gha_dir = project_path / ".github" / "workflows"
    if not gha_dir.exists():
        info("No .github/workflows directory — skipping")
    else:
        workflow_files = list(gha_dir.glob("*.yml")) + list(gha_dir.glob("*.yaml"))
        if not workflow_files:
            info("No workflow files found")
        else:
            wf_issues = 0
            for wf in workflow_files:
                content = wf.read_text(encoding="utf-8", errors="replace")
                name = wf.name

                # ① Cache poisoning vector: pull_request_target + cache
                if "pull_request_target" in content and re.search(r"actions/cache|cache@", content):
                    crit(f"{name}: pull_request_target + cache = cache-poisoning attack vector")
                    crit("   Fix: use pull_request trigger OR isolate fork-code from cache writes")
                    wf_issues += 1; total += 1

                # ② OIDC id-token: write at workflow level (should be job-scoped)
                if re.search(r"^permissions:\s*\n(.*\n)*?.*id-token:\s*write", content, re.MULTILINE):
                    warn(f"{name}: id-token: write at workflow level")
                    warn("   Fix: move to the specific publish job only")
                    wf_issues += 1

                # ③ Unsafe npm install in CI
                if re.search(r"\bnpm install\b(?!\s+--ignore-scripts)", content):
                    info(f"{name}: 'npm install' found — use 'npm ci --ignore-scripts' in CI")

                # ④ Third-party actions pinned by tag (not commit SHA)
                tag_pins = re.findall(r"uses:\s+[^/]+/[^@]+@v\d", content)
                if tag_pins:
                    warn(f"{name}: {len(tag_pins)} action(s) pinned by tag (not commit SHA)")
                    dim("  Tags can be moved — pin to commit SHA: uses: actions/checkout@<sha>")

            if wf_issues == 0:
                ok(f"Scanned {len(workflow_files)} workflow file(s) — no critical misconfigurations")
            else:
                warn(f"Found {wf_issues} workflow issue(s) across {len(workflow_files)} file(s)")

    # ── Summary ───────────────────────────────────────────────────────────────
    head("SCAN RESULT")
    if total == 0:
        ok("No infection indicators found by heuristic scan")
        ok("All checks passed")
        info("Absence of findings does NOT guarantee a clean state.")
        info("Pattern detection can be evaded. For authoritative IOC check:")
        dim(IOC_REPO)
    else:
        crit(f"{total} finding(s) detected — review output above")
        if daemon_found:
            crit("⚑  PRIORITY ACTION: daemon found → follow incident response steps")
            print()
            run_incident(brief=True)

    return total


# ═══════════════════════════════════════════════════════════════════════════════
#  MODE 2 — CHECK  (pre-install safety analysis)
# ═══════════════════════════════════════════════════════════════════════════════

def run_check(package_spec: str) -> None:
    """
    Comprehensive pre-install check for a given npm package[@version].
    Downloads the tarball without executing any scripts.
    """
    head(f"PRE-INSTALL ANALYSIS: {package_spec}")

    # ── Parse spec ────────────────────────────────────────────────────────────
    # Handles: name, name@ver, @scope/name, @scope/name@ver
    if package_spec.startswith("@"):
        tail = package_spec[1:]
        if "@" in tail:
            scope_and_name, requested_version = tail.rsplit("@", 1)
            pkg_name = f"@{scope_and_name}"
        else:
            pkg_name = f"@{tail}"
            requested_version = None
    else:
        if "@" in package_spec:
            pkg_name, requested_version = package_spec.rsplit("@", 1)
        else:
            pkg_name = package_spec
            requested_version = None

    info(f"Package : {pkg_name}")
    info(f"Version : {requested_version or 'latest'}")
    info(f"Registry: {REGISTRY_BASE}")

    risk_score = 0
    findings: List[Tuple[str, str]] = []  # (risk_level, description)

    # ── STEP 1: Registry metadata ─────────────────────────────────────────────
    subh("STEP 1/5  Registry metadata")
    encoded_name = urllib.parse.quote(pkg_name, safe="@/")
    meta = fetch_json(f"{REGISTRY_BASE}/{encoded_name}")
    if not meta:
        crit("Cannot reach registry — check package name or network access")
        return

    # Resolve version
    if not requested_version:
        requested_version = meta.get("dist-tags", {}).get("latest", "")
        info(f"Resolved latest: {requested_version}")

    all_versions = meta.get("versions", {})
    if requested_version not in all_versions:
        # Version not in registry — check if this is a known-bad version (pulled by npm)
        if pkg_name in KNOWN_BAD and requested_version in KNOWN_BAD[pkg_name].get("bad", []):
            crit(f"Version {requested_version} NOT in registry — it was removed by npm")
            crit(f"CONFIRMED MALICIOUS: {pkg_name}@{requested_version} was a Shai-Hulud payload version")
            crit(f"Waves: {', '.join(KNOWN_BAD[pkg_name].get('waves', []))}")
            crit("DO NOT install. This version was actively compromised and pulled.")
        else:
            crit(f"Version '{requested_version}' not found in registry")
            info(f"Available dist-tags: {list(meta.get('dist-tags', {}).keys())}")
        return

    version_meta = all_versions[requested_version]
    time_data     = meta.get("time", {})
    publish_ts    = time_data.get(requested_version)

    # Publish age check
    if publish_ts:
        publish_dt = datetime.fromisoformat(publish_ts.replace("Z", "+00:00"))
        age_total_hours = (datetime.now(timezone.utc) - publish_dt).total_seconds() / 3600
        age_days = int(age_total_hours // 24)
        age_hours = int(age_total_hours % 24)
        ok(f"Published : {publish_ts[:19]}Z  ({age_days}d {age_hours}h ago)")

        if age_total_hours < 6:
            crit(f"Published {age_hours}h ago — CRITICAL risk window (wave 5 published and spread in <6h)")
            risk_score += 40
            findings.append(("CRITICAL", f"Published only {age_hours}h ago — attack window is active"))
        elif age_total_hours < 24:
            warn(f"Published {age_hours}h ago — active attack risk window")
            risk_score += 25
            findings.append(("HIGH", f"Published {int(age_total_hours)}h ago (24h risk window)"))
        elif age_days < 7:
            warn(f"Published {age_days}d ago — below recommended min-release-age of 7d")
            risk_score += 10
            findings.append(("MEDIUM", f"Published {age_days}d ago (set npm config min-release-age=7d)"))
        else:
            ok(f"Package age exceeds 7-day minimum release age heuristic")
    else:
        warn("Publish timestamp unavailable")

    # Maintainer count
    maintainers = version_meta.get("maintainers", meta.get("maintainers", []))
    ok(f"Maintainers: {len(maintainers)}  ({', '.join(m.get('name','?') for m in maintainers[:5])})")
    if len(maintainers) == 1:
        info("Single-maintainer package: one account compromise = full package compromise")

    # Total published versions
    total_versions = len(all_versions)
    ok(f"Total versions in registry: {total_versions}")

    # ── STEP 2: Known-bad version check ───────────────────────────────────────
    subh("STEP 2/5  Known compromised version database")
    if pkg_name in KNOWN_BAD:
        entry = KNOWN_BAD[pkg_name]
        bad_versions = entry.get("bad", [])
        waves = entry.get("waves", [])
        if bad_versions and requested_version in bad_versions:
            crit(f"CONFIRMED COMPROMISED: {pkg_name}@{requested_version}")
            crit(f"Campaign wave(s): {', '.join(waves)}")
            crit("DO NOT INSTALL. This version is in the confirmed-malicious list.")
            risk_score += 100
            findings.append(("CRITICAL", f"Confirmed compromised version (wave: {', '.join(waves)})"))
        else:
            warn(f"{pkg_name} is a known Shai-Hulud high-value target (prior waves: {', '.join(waves)})")
            warn(f"Version {requested_version} not in confirmed-bad list, but heightened scrutiny applied")
            risk_score += 15
            findings.append(("MEDIUM", "Package is a known repeated Shai-Hulud target"))
    elif pkg_name in HIGH_VALUE_TARGETS:
        warn(f"{pkg_name} is in the high-value target set — applying heightened scrutiny")
        risk_score += 10
    else:
        ok("Package not in known-compromised or high-value-target lists")

    dim(f"Known-bad list lags active attacks → always cross-check: {IOC_REPO}")

    # ── STEP 3: Lifecycle script inspection (from registry) ───────────────────
    subh("STEP 3/5  Lifecycle scripts  (from registry metadata — no execution)")
    scripts = version_meta.get("scripts", {})
    risky_hooks = ["preinstall", "install", "postinstall", "prepare"]
    any_hook = False
    for hook in risky_hooks:
        if hook in scripts:
            any_hook = True
            val = scripts[hook]
            hits = scan_text(val)
            if hits:
                for desc, risk, snippet in hits:
                    fn = crit if risk == "CRITICAL" else warn
                    fn(f"{risk} in [{hook}]: {desc}")
                    dim(f"Script text: {val[:150]}")
                    risk_score += 45 if risk == "CRITICAL" else 20 if risk == "HIGH" else 8
                    findings.append((risk, f"[{hook}] — {desc}"))
            else:
                # Hook exists but patterns clean — still worth reporting
                info(f"[{hook}] hook present: {val[:100]}")
                if hook == "preinstall":
                    warn("preinstall hook runs before install — verify manually")
                    risk_score += 5
                    findings.append(("LOW", "preinstall hook present (manual review needed)"))

    if not any_hook:
        ok("No preinstall / install / postinstall / prepare hooks declared")
    else:
        dim("  --ignore-scripts blocks these hooks but does NOT prevent tarball extraction")
        dim("  Use 'npm pack <pkg>' + manual inspect before 'npm ci --ignore-scripts'")

    # ── STEP 4: Dependency source check ───────────────────────────────────────
    subh("STEP 4/5  Dependency source validation  (git / non-registry deps)")
    all_dep_specs: Dict[str, str] = {}
    all_dep_specs.update(version_meta.get("dependencies", {}))
    all_dep_specs.update(version_meta.get("optionalDependencies", {}))

    git_prefixes = ("git+", "git://", "github:", "bitbucket:", "gitlab:", "file:", "http://", "https://")
    git_deps = {k: v for k, v in all_dep_specs.items()
                if any(v.startswith(p) for p in git_prefixes)}

    if git_deps:
        warn(f"{len(git_deps)} non-registry (git/file/url) dependencies:")
        for dep, spec in git_deps.items():
            warn(f"   {dep}: {spec}")
        dim("  These execute 'prepare' hooks during install — even with --ignore-scripts on the root package")
        risk_score += min(len(git_deps) * 12, 30)
        findings.append(("MEDIUM", f"{len(git_deps)} non-registry dep(s) execute prepare hooks on install"))
    else:
        ok(f"All {len(all_dep_specs)} dependencies reference npm registry")

    # ── STEP 5: Tarball download and deep scan ─────────────────────────────────
    subh("STEP 5/5  Tarball download and deep-content scan  (no execution)")
    dist     = version_meta.get("dist", {})
    tarball_url = dist.get("tarball")
    shasum   = dist.get("shasum")         # SHA-1 (legacy)
    integrity = dist.get("integrity")    # SHA-512 SRI (preferred)

    if not tarball_url:
        warn("No tarball URL in registry metadata — cannot proceed with content scan")
    else:
        info(f"Downloading: {tarball_url}")
        info("(tarball is inspected in memory — no code is executed)")
        t0 = time.time()
        tarball_bytes = fetch_bytes(tarball_url)
        elapsed = time.time() - t0

        if not tarball_bytes:
            warn("Download failed — skipping content scan")
        else:
            size_kb = len(tarball_bytes) / 1024
            ok(f"Downloaded: {size_kb:.1f} KB in {elapsed:.1f}s")

            # Integrity verification
            if integrity and integrity.startswith("sha512-"):
                expected_b64 = integrity[7:]
                actual_digest = hashlib.sha512(tarball_bytes).digest()
                actual_b64 = base64.b64encode(actual_digest).decode()
                if actual_b64 == expected_b64:
                    ok("Tarball integrity verified (SHA-512 ✓)")
                else:
                    crit("INTEGRITY MISMATCH — SHA-512 does not match registry record")
                    crit("Tarball may have been tampered with in transit or at registry")
                    risk_score += 100
                    findings.append(("CRITICAL", "Tarball SHA-512 integrity check FAILED"))
            elif shasum:
                actual_sha1 = hashlib.sha1(tarball_bytes).hexdigest()
                if actual_sha1 == shasum:
                    ok("Tarball integrity verified (SHA-1 ✓)")
                else:
                    crit("INTEGRITY MISMATCH — SHA-1 does not match registry record")
                    risk_score += 100
                    findings.append(("CRITICAL", "Tarball SHA-1 integrity check FAILED"))
            else:
                warn("No integrity hash available from registry — cannot verify tarball")

            # Tarball size heuristic
            # router_init.js payload was ~2.3 MB (the whole tarball would be larger)
            if size_kb > 800:
                warn(f"Unusually large tarball ({size_kb:.0f} KB)")
                warn("  The Shai-Hulud router_init.js payload alone was ~2.3 MB")
                risk_score += 10
                findings.append(("LOW", f"Large tarball ({size_kb:.0f} KB) — review file list"))

            # Deep content scan
            info("Scanning tarball contents for malicious indicators...")
            tb_findings = scan_tarball_bytes(tarball_bytes)
            if tb_findings:
                for filepath, desc, risk, snippet in tb_findings:
                    fn = crit if risk == "CRITICAL" else warn
                    fn(f"{risk} in {filepath}")
                    fn(f"   → {desc}")
                    if snippet != Path(filepath).name:
                        dim(f"   match: {snippet[:100]}")
                    risk_score += 50 if risk == "CRITICAL" else 20 if risk == "HIGH" else 4
                    findings.append((risk, f"In file {filepath}: {desc}"))
            else:
                ok("No malicious patterns detected in tarball contents")

    # ── Risk report ───────────────────────────────────────────────────────────
    head("PRE-INSTALL RISK REPORT")
    info(f"Package : {pkg_name}@{requested_version}")
    capped = min(risk_score, 100)

    if capped == 0:
        ok(f"Risk score: 0/100 — No indicators found")
        ok("Proceed — but read limitations below before running npm install")
    elif capped < 15:
        ok(f"Risk score: {capped}/100 — Low risk")
        info("Manual review of findings recommended before install")
    elif capped < 40:
        warn(f"Risk score: {capped}/100 — Moderate risk — verify independently")
        warn("Use Socket.dev or Snyk for behavioral analysis before installing in production")
    elif capped < 70:
        warn(f"Risk score: {capped}/100 — High risk — do not install without investigation")
    else:
        crit(f"Risk score: {capped}/100 — CRITICAL — do not install")

    if findings:
        print()
        info("Findings summary:")
        for level, msg in findings:
            (crit if level == "CRITICAL" else warn if level in ("HIGH",) else
             warn if level == "MEDIUM" else info)(f"  [{level}]  {msg}")

    # ── Safe install workflow ─────────────────────────────────────────────────
    subh("Safe install workflow (if proceeding)")
    print(f"""
     # Step A — install WITHOUT executing any lifecycle scripts
     npm install {pkg_name}@{requested_version} --ignore-scripts

     # Step B — manually inspect the installed package
     cat node_modules/{pkg_name.lstrip('@').replace('/', '/node_modules/')}/package.json | python3 -c "import sys,json; d=json.load(sys.stdin); print(json.dumps(d.get('scripts',{{}}), indent=2))"

     # Step C — search for known payload filenames
     find node_modules/{pkg_name} -name "router_init.js" -o -name "setup_bun.js" -o -name "bun_environment.js" 2>/dev/null

     # Step D — only after manual review, allow postinstall if package requires it
     # npm rebuild {pkg_name}@{requested_version}
    """)

    # ── Limitations note ──────────────────────────────────────────────────────
    subh("Limitations of this tool")
    dim("• Novel obfuscation (encoding, split strings, dynamic eval) can evade pattern matching")
    dim("• Known-bad list is manually maintained and lags zero-day variants")
    dim("• 'Risk score 0' is not a guarantee — it means no KNOWN patterns were found")
    dim("• Behavioral analysis (Socket, Snyk, Wiz) provides deeper protection in CI pipelines")
    dim(f"• Cross-check IOC list before any production deploy: {IOC_REPO}")
    print()


# ═══════════════════════════════════════════════════════════════════════════════
#  MODE 3 — INCIDENT RESPONSE
# ═══════════════════════════════════════════════════════════════════════════════

def run_incident(brief: bool = False) -> None:
    if not brief:
        head("INCIDENT RESPONSE GUIDE — Shai-Hulud Worm")
        info("Source: CISA alert + Wiz + Datadog postmortems")
        print()

    steps = [
        ("STEP 1 — STOP  (do NOT revoke tokens yet)", [
            "The worm installs a daemon (gh-token-monitor) that polls GitHub every 60 seconds.",
            "If it detects a token revocation, it triggers:  rm -rf ~/  (Linux/macOS)",
            "or the Windows equivalent — wiping your entire home directory.",
            "The daemon self-destructs after 24 hours, so act within that window.",
        ]),
        ("STEP 2 — ISOLATE THE MACHINE", [
            "Pull the ethernet cable or disable Wi-Fi — cut all network access.",
            "For a CI/CD runner: stop the runner service, do not cancel the active job.",
            "Do not log in to any accounts from the infected machine.",
        ]),
        ("STEP 3 — IMAGE (recommended for forensics)", [
            "Linux:   sudo dd if=/dev/sda bs=4M | gzip > ~/backup_$(date +%Y%m%d).img.gz",
            "macOS:   Use Disk Utility > Image > Device Image before proceeding.",
            "CI/CD:   Take a VM snapshot if the runner is virtualized.",
        ]),
        ("STEP 4 — REMOVE THE DAEMON  (before reconnecting)", [
            "Linux (systemd):",
            "  systemctl --user stop gh-token-monitor",
            "  systemctl --user disable gh-token-monitor",
            "  rm ~/.config/systemd/user/gh-token-monitor.service",
            "  systemctl --user daemon-reload",
            "",
            "macOS (LaunchAgent):",
            "  launchctl unload ~/Library/LaunchAgents/com.user.gh-token-monitor.plist",
            "  rm ~/Library/LaunchAgents/com.user.gh-token-monitor.plist",
            "",
            "Windows:",
            "  schtasks /query | findstr gh-token",
            "  schtasks /delete /tn <task-name> /f",
        ]),
        ("STEP 5 — ROTATE ALL CREDENTIALS  (after daemon is confirmed removed)", [
            "GitHub PATs:    Settings → Developer settings → PATs → Revoke all",
            "npm tokens:     npm token list  →  npm token revoke <id>  (for each)",
            "AWS:            IAM → Security credentials → Access keys → Delete all",
            "GCP:            IAM → Service accounts → Keys → Delete all keys",
            "Azure:          App registrations → Certificates & secrets → Delete all",
            "CI/CD secrets:  GitHub Actions, GitLab CI, CircleCI — rotate everything",
            "SSH keys:       Generate new keypair, remove old authorized_keys entries",
        ]),
        ("STEP 6 — AUDIT WHAT WAS PUBLISHED", [
            "Check your npm publish history: npm access ls-packages <your-username>",
            "Review GitHub Actions runs for unexpected 'npm publish' steps.",
            "Search GitHub for repos with 'Shai-Hulud' or 'Here We Go Again' in description.",
            "If any of your packages were backdoored: notify downstream users immediately.",
            "File advisory at: https://github.com/advisories/new",
        ]),
        ("STEP 7 — CLEAN ENVIRONMENT", [
            "Wipe and reinstall the OS — do NOT attempt to clean in place.",
            "Rebuild all Docker images and CI runners from a verified base image.",
            "Do NOT reuse any secret that was present on the infected machine.",
            "Generate new SSH keys, npm tokens, GitHub PATs from a clean machine.",
        ]),
        ("STEP 8 — REPORT", [
            "npm security:   security@npmjs.com",
            "GitHub:         https://github.com/contact/security",
            "CISA:           https://www.cisa.gov/reporting",
            f"IOC submission: {IOC_REPO}",
            "StepSecurity:   https://www.stepsecurity.io  (attribution research)",
        ]),
    ]

    for title, items in steps:
        print(_c(f"\n  {title}", "1;33"))
        for item in items:
            if item == "":
                print()
            elif item.startswith("  "):
                print(_c(f"      {item}", "2"))
            else:
                print(f"    • {item}")

    if not brief:
        print()
        info("Recovery time estimate: 2–4 hours for individual dev, 1–2 days for CI/CD rebuild")
        info("Do not rush step 5 — partial rotation leaves attack surface open")
        print()


# ═══════════════════════════════════════════════════════════════════════════════
#  ENTRYPOINT
# ═══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    banner = textwrap.dedent(f"""
    ╔═══════════════════════════════════════════════════════════════╗
    ║  shai_hulud_guard  v{VERSION:<8}                              ║
    ║  npm supply-chain worm scanner  |  all waves Sept 2025–now   ║
    ║  Zero external dependencies  |  Python 3.8+                  ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)

    parser = argparse.ArgumentParser(
        description="Shai-Hulud npm worm scanner and pre-install safety checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        examples:
          python shai_hulud_guard.py --scan
          python shai_hulud_guard.py --scan --path ~/projects/myapp
          python shai_hulud_guard.py --check @tanstack/react-router
          python shai_hulud_guard.py --check @tanstack/react-router@1.169.5
          python shai_hulud_guard.py --incident
        """),
    )
    parser.add_argument(
        "--scan", action="store_true",
        help="Scan existing project for infection indicators",
    )
    parser.add_argument(
        "--path", default=".",
        help="Project root for --scan (default: current directory)",
    )
    parser.add_argument(
        "--check", metavar="PKG[@VERSION]",
        help="Pre-install safety check for an npm package",
    )
    parser.add_argument(
        "--incident", action="store_true",
        help="Print incident response guide",
    )
    parser.add_argument(
        "--version", action="version", version=f"shai_hulud_guard {VERSION}",
    )

    args = parser.parse_args()
    print(banner)

    if args.scan:
        run_scan(Path(args.path))
    elif args.check:
        run_check(args.check)
    elif args.incident:
        run_incident()
    else:
        parser.print_help()
        print()
        info("Start with:  python shai_hulud_guard.py --scan")
        info("Check pkg:   python shai_hulud_guard.py --check <package>")
        info("Compromised: python shai_hulud_guard.py --incident")


if __name__ == "__main__":
    main()
