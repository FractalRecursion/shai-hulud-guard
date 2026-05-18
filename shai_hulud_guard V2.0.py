#!/usr/bin/env python3
"""
shai_hulud_guard.py  v2.0.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Interactive scanner, auto-fixer, hardening assistant, and diagnosis reporter
for the Shai-Hulud npm supply-chain worm family (all waves, Sept 2025 → now).

Flow:  SCAN → REPORT → FIX (safe, no tradeoffs) → PROTECT (with tradeoffs)
       → DIAGNOSE (LLM-ready report)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Usage:
  python shai_hulud_guard.py              # interactive mode (recommended)
  python shai_hulud_guard.py --path DIR   # scan a specific project directory
  python shai_hulud_guard.py --check PKG  # pre-install check (non-interactive)

Build single .exe (Windows / macOS / Linux):
  pip install pyinstaller
  pyinstaller --onefile --name shai_hulud_guard shai_hulud_guard.py

Requirements: Python 3.8+ — zero external dependencies
"""

import argparse
import base64
import dataclasses
import hashlib
import io
import json
import os
import platform
import re
import subprocess
import sys
import tarfile
import time
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

# ═══════════════════════════════════════════════════════════════════════════════
#  VERSION
# ═══════════════════════════════════════════════════════════════════════════════

VERSION       = "2.0.0"
REGISTRY_BASE = "https://registry.npmjs.org"
IOC_REPO      = "https://github.com/DataDog/indicators-of-compromise/tree/main/shai-hulud-2.0"
REPORT_PREFIX = "shai_hulud_report"

# ═══════════════════════════════════════════════════════════════════════════════
#  IOC CONSTANTS  (sourced from CISA, Datadog, Wiz, StepSecurity post-mortems)
# ═══════════════════════════════════════════════════════════════════════════════

MALICIOUS_FILENAMES = {
    "router_init.js",
    "setup_bun.js",
    "bun_environment.js",
    "setup.mjs",
}

MALICIOUS_PATTERNS: List[Tuple[str, str, str]] = [
    (r"Sha[i1].?Hulud",                                "Worm identity string",                    "CRITICAL"),
    (r"Here We Go Again|The Second Coming",            "Worm campaign tag",                       "CRITICAL"),
    (r"TeamPCP|DeadCatx3|PCPcat|ShellForce|CipherForce","Known threat actor",                    "CRITICAL"),
    (r"gh.?token.?monitor",                            "Daemon name",                             "CRITICAL"),
    (r"A Mini Shai.?Hulud has Appeared",               "Worm repo tag",                           "CRITICAL"),
    (r"rm\s+-rf\s+[\"']?[~$]|rm\s+-rf\s+\$HOME",      "Home-dir wipe (Linux/macOS)",             "CRITICAL"),
    (r"Remove-Item\s+.*-Recurse.*Home|rmdir\s+/s\s+/q\s+.*%USERPROFILE%",
                                                        "Home-dir wipe (Windows)",                "CRITICAL"),
    (r"git-tanstack\.com",                             "C2 typosquat domain",                     "CRITICAL"),
    (r"webhook\.site\/[a-f0-9\-]{36}",                "Known exfil endpoint",                    "CRITICAL"),
    (r"getsession\.org|oxen\.io",                      "Session network C2 channel",              "HIGH"),
    (r"ghp_[A-Za-z0-9]{36}",                          "GitHub PAT literal",                      "CRITICAL"),
    (r"gho_[A-Za-z0-9]{36}",                          "GitHub OAuth token literal",              "CRITICAL"),
    (r"npm_[A-Za-z0-9]{36}",                          "npm token literal",                       "CRITICAL"),
    (r"application_default_credentials\.json",         "GCP credential file access",             "HIGH"),
    (r"\.aws[/\\]credentials|AWS_SECRET_ACCESS_KEY",   "AWS credential access",                  "HIGH"),
    (r"AZURE_CLIENT_SECRET|AZURE_TENANT_ID",           "Azure credential access",                "HIGH"),
    (r"id_rsa|id_ed25519|id_ecdsa",                    "SSH private key access",                 "HIGH"),
    (r"bun\.sh/install|curl.*bun\.sh",                 "Bun installer in lifecycle script",       "HIGH"),
    (r"\"bun\"\s*,?\s*\"run\"|spawn.*bun\b",           "Bun payload execution",                  "HIGH"),
    (r"/proc/\d+/mem|ptrace|process_vm_readv",         "Runner memory extraction",               "CRITICAL"),
    (r"ACTIONS_ID_TOKEN_REQUEST_URL",                  "GitHub OIDC token ENV access",           "HIGH"),
    (r"LaunchAgents.*com\.user\.",                     "macOS LaunchAgent persistence",           "CRITICAL"),
    (r"systemd/user.*\.service",                       "Linux systemd persistence",               "CRITICAL"),
    (r"SCHTASKS|schtasks\.exe",                        "Windows Task Scheduler persistence",      "HIGH"),
    (r"eval\s*\(\s*(atob|Buffer|decodeURI)",           "eval of decoded content",                "HIGH"),
    (r"Buffer\.from\([^,]+,\s*['\"]base64['\"]",       "Base64 decode in script",               "MEDIUM"),
    (r"(?:\\u00[2-7][0-9a-fA-F]){4,}",                "ASCII chars encoded as \\u escapes",     "MEDIUM"),
    (r"api\.github\.com/user/repos",                   "GitHub API repo creation (credential dump)", "HIGH"),
    (r"pull_request_target",                           "pull_request_target (cache poison vector)", "MEDIUM"),
]

KNOWN_BAD: Dict[str, dict] = {
    "@tanstack/react-router": {"bad": ["1.169.5"],  "waves": ["Wave5-May2026"]},
    "@tanstack/router":       {"bad": ["1.169.5"],  "waves": ["Wave5-May2026"]},
    "@tanstack/react-query":  {"bad": [],            "waves": ["Wave5-May2026"]},
    "@mistralai/mistralai":   {"bad": [],            "waves": ["Wave5-May2026"]},
    "@uipath/apollo-core":    {"bad": [],            "waves": ["Wave5-May2026"]},
    "guardrails-ai":          {"bad": ["0.10.1"],   "waves": ["Wave5-May2026"]},
    "mistralai":              {"bad": ["2.4.6"],    "waves": ["Wave5-May2026"]},
    "@bitwarden/cli":         {"bad": [],            "waves": ["Wave4-Apr2026"]},
    "intercom-client":        {"bad": ["7.0.4"],    "waves": ["Wave5-May2026"]},
    "tinycolor2":             {"bad": [],            "waves": ["Wave1-Sep2025"]},
    "@asyncapi/cli":          {"bad": [],            "waves": ["Wave2-Nov2025"]},
}

HIGH_VALUE_TARGETS = set(KNOWN_BAD.keys()) | {
    "@tanstack/form", "@tanstack/table", "@tanstack/virtual",
    "@tanstack/store", "@tanstack/start", "@tanstack/query-core",
    "@squawk/core", "@opensearch-project/opensearch",
}

DAEMON_PATHS = {
    "linux":  [Path.home() / ".config" / "systemd" / "user" / "gh-token-monitor.service"],
    "darwin": [Path.home() / "Library" / "LaunchAgents" / "com.user.gh-token-monitor.plist"],
    "windows": [],
}

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
#  TERMINAL UI
# ═══════════════════════════════════════════════════════════════════════════════

def _enable_ansi_windows():
    if platform.system() == "Windows":
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleMode(
                ctypes.windll.kernel32.GetStdHandle(-11), 7)
        except Exception:
            pass

_enable_ansi_windows()
_COL = sys.stdout.isatty()

def _c(t: str, code: str) -> str:
    return f"\033[{code}m{t}\033[0m" if _COL else t

def clr():
    os.system("cls" if os.name == "nt" else "clear")

def ok(m):    print(_c(f"  \u2713  {m}", "32"))
def warn(m):  print(_c(f"  \u26a0  {m}", "33"))
def crit(m):  print(_c(f"  \u2717  {m}", "31;1"))
def info(m):  print(_c(f"  \u2192  {m}", "36"))
def dim(m):   print(_c(f"     {m}", "2"))
def bold(m):  print(_c(m, "1"))

def hr(char="\u2550", width=64):
    print(_c(char * width, "2"))

def head(title: str):
    print()
    hr()
    print(_c(f"  {title}", "1"))
    hr()

def subh(title: str):
    print()
    print(_c(f"  \u250c\u2500 {title}", "1;36"))

def banner():
    clr()
    print(_c("""
  \u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557
  \u2551   SHAI-HULUD GUARD  v2.0.0                                  \u2551
  \u2551   npm supply-chain worm scanner \u00b7 fixer \u00b7 hardening         \u2551
  \u2551   All waves: Sept 2025 \u2192 present  |  Zero dependencies      \u2551
  \u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d
""", "1"))

def menu(title: str, options: List[Tuple[str, str]]) -> str:
    print()
    bold(f"  {title}")
    print()
    for key, label in options:
        print(f"    [{_c(key,'1;33')}]  {label}")
    print()
    valid = {k.upper() for k, _ in options}
    while True:
        try:
            choice = input(_c("  Your choice: ", "33")).strip().upper()
        except EOFError:
            sys.exit(0)
        if choice in valid:
            return choice
        print(_c(f"  Invalid \u2014 enter one of: {', '.join(sorted(valid))}", "31"))

def confirm(prompt: str, default: bool = False) -> bool:
    hint = "[Y/n]" if default else "[y/N]"
    try:
        ans = input(_c(f"  {prompt} {hint}: ", "33")).strip().lower()
    except EOFError:
        return default
    if not ans:
        return default
    return ans in ("y", "yes")

def pause(msg: str = "Press Enter to continue..."):
    try:
        input(_c(f"\n  {msg}", "2"))
    except EOFError:
        pass

def tick(label: str, i: int = 0):
    spinner = ["\u25cb", "\u25d4", "\u25d1", "\u25d5"][i % 4]
    print(_c(f"\r  {spinner}  {label:<55}", "36"), end="", flush=True)

def done_line(label: str):
    print(_c(f"\r  \u2713  {label:<55}", "32"))

# ═══════════════════════════════════════════════════════════════════════════════
#  SYSTEM INFO
# ═══════════════════════════════════════════════════════════════════════════════

def collect_system_info() -> dict:
    def run(cmd: List[str]) -> str:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return r.stdout.strip().splitlines()[0] if r.stdout.strip() else "unavailable"
        except Exception:
            return "unavailable"

    return {
        "os":           f"{platform.system()} {platform.release()} ({platform.machine()})",
        "os_version":   platform.version(),
        "python":       platform.python_version(),
        "cpu":          platform.processor() or platform.machine(),
        "node_version": run(["node", "--version"]),
        "npm_version":  run(["npm", "--version"]),
        "git_version":  run(["git", "--version"]),
        "hostname":     platform.node(),
        "user":         os.environ.get("USER") or os.environ.get("USERNAME") or "unknown",
        "ci_env":       os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS") or "none",
        "shell":        os.environ.get("SHELL") or os.environ.get("COMSPEC") or "unknown",
        "scanned_at":   datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }

# ═══════════════════════════════════════════════════════════════════════════════
#  FINDING
# ═══════════════════════════════════════════════════════════════════════════════

@dataclasses.dataclass
class Finding:
    check:      str
    level:      str   # CRITICAL | HIGH | MEDIUM | LOW | INFO
    title:      str
    detail:     str
    path:       str = ""
    fixable:    bool = False
    fix_label:  str = ""
    fix_fn:     Optional[Callable] = dataclasses.field(default=None, repr=False)

    def _icon(self) -> str:
        return {"CRITICAL": "\u2717", "HIGH": "\u26a0", "MEDIUM": "\u26a0",
                "LOW": "\u2192", "INFO": "\u2192"}.get(self.level, "\u00b7")

    def _col(self) -> str:
        return {"CRITICAL": "31;1", "HIGH": "33", "MEDIUM": "33",
                "LOW": "36", "INFO": "36"}.get(self.level, "0")

    def display(self):
        print(_c(f"  {self._icon()}  [{self.level}] {self.title}", self._col()))
        for line in self.detail.splitlines():
            dim(line)
        if self.path:
            dim(f"Path: {self.path}")
        if self.fixable:
            print(_c(f"     \u2192 Auto-fixable: {self.fix_label}", "32"))

# ═══════════════════════════════════════════════════════════════════════════════
#  PATTERN ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

def scan_text(text: str) -> List[Tuple[str, str, str]]:
    seen: set = set()
    out = []
    for pattern, desc, risk in MALICIOUS_PATTERNS:
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            key = (desc, risk)
            if key not in seen:
                seen.add(key)
                out.append((desc, risk, m.group(0)[:100]))
    return out

def scan_tarball_bytes(data: bytes) -> List[Tuple[str, str, str, str]]:
    TEXT_EXT = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".json",
                ".sh", ".bash", ".py", ".yml", ".yaml", ".env"}
    out = []
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            for m in tf.getmembers():
                if not m.isfile():
                    continue
                base = Path(m.name).name
                if base in MALICIOUS_FILENAMES:
                    out.append((m.name, f"Known payload filename: {base}", "CRITICAL", base))
                if Path(m.name).suffix.lower() in TEXT_EXT:
                    try:
                        fobj = tf.extractfile(m)
                        if fobj:
                            content = fobj.read().decode("utf-8", errors="replace")
                            for desc, risk, snip in scan_text(content):
                                out.append((m.name, desc, risk, snip))
                    except Exception:
                        pass
    except Exception as e:
        warn(f"Could not read tarball: {e}")
    return out

# ═══════════════════════════════════════════════════════════════════════════════
#  SCANNER  — 6 checks, structured findings
# ═══════════════════════════════════════════════════════════════════════════════

def run_scan(project_path: Path) -> List[Finding]:
    findings: List[Finding] = []
    plat = platform.system().lower()

    # ── 1. Persistence daemon ─────────────────────────────────────────────────
    tick("Check 1/6: Persistence daemon")
    for dp in DAEMON_PATHS.get(plat, []):
        if dp.exists():
            def _daemon_fix(path=dp, system=plat):
                def fix():
                    try:
                        if system == "linux":
                            subprocess.run(["systemctl", "--user", "stop",    "gh-token-monitor"], capture_output=True, check=False)
                            subprocess.run(["systemctl", "--user", "disable", "gh-token-monitor"], capture_output=True, check=False)
                        elif system == "darwin":
                            subprocess.run(["launchctl", "unload", str(path)], capture_output=True, check=False)
                        path.unlink()
                        if system == "linux":
                            subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True, check=False)
                        return True, f"Daemon stopped and deleted: {path}"
                    except Exception as e:
                        return False, str(e)
                return fix
            findings.append(Finding(
                check="Daemon",
                level="CRITICAL",
                title="Persistence daemon FOUND — active infection confirmed",
                detail=(
                    "gh-token-monitor polls GitHub every 60s.\n"
                    "Token revocation triggers: rm -rf ~/\n"
                    "\u26a1 DO NOT revoke tokens until this daemon is removed first."
                ),
                path=str(dp),
                fixable=True,
                fix_label="Stop service and delete daemon file",
                fix_fn=_daemon_fix(),
            ))
    done_line("Check 1/6: Persistence daemon")

    # ── 2. package.json ───────────────────────────────────────────────────────
    tick("Check 2/6: package.json audit")
    pkg_json_path = project_path / "package.json"
    if pkg_json_path.exists():
        try:
            pkg_data = json.loads(pkg_json_path.read_text(encoding="utf-8", errors="replace"))
            all_deps: Dict[str, str] = {}
            for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                all_deps.update(pkg_data.get(section, {}))
            for dep, ver_spec in all_deps.items():
                clean_ver = re.sub(r"[^0-9.]", "", ver_spec)
                if dep in KNOWN_BAD:
                    entry = KNOWN_BAD[dep]
                    if entry["bad"] and clean_ver in entry["bad"]:
                        findings.append(Finding(
                            check="Packages",
                            level="CRITICAL",
                            title=f"Confirmed compromised package: {dep}@{clean_ver}",
                            detail=f"Waves: {', '.join(entry['waves'])}\nRemove from package.json and reinstall.",
                            path=str(pkg_json_path),
                        ))
                    elif dep in HIGH_VALUE_TARGETS:
                        findings.append(Finding(
                            check="Packages",
                            level="HIGH",
                            title=f"High-value Shai-Hulud target installed: {dep}@{ver_spec}",
                            detail=f"Previously attacked in: {', '.join(entry['waves'])}",
                        ))
                if any(ver_spec.startswith(p) for p in ("git", "github:", "bitbucket:", "gitlab:", "file:")):
                    findings.append(Finding(
                        check="Packages",
                        level="HIGH",
                        title=f"Non-registry dep bypasses --ignore-scripts: {dep}",
                        detail=f"Source: {ver_spec}\nGit/file deps run prepare hooks unconditionally.",
                    ))
        except Exception as e:
            findings.append(Finding(check="Packages", level="INFO", title="Could not parse package.json", detail=str(e)))
    else:
        findings.append(Finding(check="Packages", level="INFO",
                                title="No package.json found",
                                detail="Use --path to point at a project root with package.json"))
    done_line("Check 2/6: package.json audit")

    # ── 3. Lock file and npmrc ────────────────────────────────────────────────
    tick("Check 3/6: Lock file and npmrc hygiene")
    lockfiles = ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"]
    if not any((project_path / lf).exists() for lf in lockfiles):
        findings.append(Finding(
            check="Hygiene",
            level="MEDIUM",
            title="No lock file — dependency versions not pinned",
            detail="Run: npm install  (generates package-lock.json)\nCI must use: npm ci  — not npm install",
        ))
    npmrc_global = Path.home() / ".npmrc"
    if npmrc_global.exists():
        content = npmrc_global.read_text(encoding="utf-8", errors="replace")
        if "min-release-age" not in content:
            findings.append(Finding(
                check="Hygiene",
                level="MEDIUM",
                title="Global ~/.npmrc missing min-release-age=7d",
                detail="Wave 5 spread in <6h. A 7-day delay blocks the entire documented attack window.",
            ))
    else:
        findings.append(Finding(
            check="Hygiene",
            level="MEDIUM",
            title="No global ~/.npmrc configured",
            detail="npm security settings are not hardened.",
        ))
    done_line("Check 3/6: Lock file and npmrc hygiene")

    # ── 4. node_modules ───────────────────────────────────────────────────────
    nm_path = project_path / "node_modules"
    if nm_path.exists():
        pkg_dirs: List[Path] = []
        for entry in nm_path.iterdir():
            if entry.name.startswith("@") and entry.is_dir():
                pkg_dirs.extend(e for e in entry.iterdir() if e.is_dir())
            elif entry.is_dir() and not entry.name.startswith("."):
                pkg_dirs.append(entry)
        total = len(pkg_dirs)
        for i, pdir in enumerate(pkg_dirs):
            if i % 25 == 0:
                tick(f"Check 4/6: node_modules ({i}/{total} packages)", i)
            # Payload filenames
            for fname in MALICIOUS_FILENAMES:
                fp = pdir / fname
                if fp.exists():
                    def _file_fix(fpath=fp):
                        def fix():
                            try:
                                fpath.unlink()
                                return True, f"Deleted {fpath}"
                            except Exception as e:
                                return False, str(e)
                        return fix
                    findings.append(Finding(
                        check="node_modules",
                        level="CRITICAL",
                        title=f"Payload file: {fname} in {pdir.name}",
                        detail="Shai-Hulud exclusive filename — no legitimate use case.",
                        path=str(fp),
                        fixable=True,
                        fix_label=f"Delete {fp.name}",
                        fix_fn=_file_fix(),
                    ))
            # Lifecycle scripts
            meta_path = pdir / "package.json"
            if meta_path.exists():
                try:
                    meta = json.loads(meta_path.read_text(encoding="utf-8", errors="replace"))
                    pkg_name_str = meta.get("name", pdir.name)
                    for hook in ("preinstall", "install", "postinstall", "prepare"):
                        if hook in meta.get("scripts", {}):
                            hits = scan_text(meta["scripts"][hook])
                            for desc, risk, snip in hits:
                                findings.append(Finding(
                                    check="node_modules",
                                    level=risk,
                                    title=f"[{hook}] {pkg_name_str}: {desc}",
                                    detail=f"Script: {meta['scripts'][hook][:200]}\nMatch: {snip}",
                                    path=str(meta_path),
                                ))
                except Exception:
                    pass
        done_line(f"Check 4/6: node_modules ({total} packages scanned)")
    else:
        done_line("Check 4/6: node_modules (not present — skipped)")

    # ── 5. Credential files ───────────────────────────────────────────────────
    tick("Check 5/6: Credential file exposure")
    exposed = [f for f in CREDENTIAL_FILES if f.exists()]
    if exposed:
        findings.append(Finding(
            check="Credentials",
            level="HIGH",
            title=f"{len(exposed)} credential file(s) on disk — worm sweep targets",
            detail="\n".join(str(f) for f in exposed) +
                   "\nRotate all credentials in these files if infection is confirmed.",
        ))
    done_line("Check 5/6: Credential file exposure")

    # ── 6. GitHub Actions ─────────────────────────────────────────────────────
    tick("Check 6/6: GitHub Actions workflows")
    gha_dir = project_path / ".github" / "workflows"
    if gha_dir.exists():
        for wf in list(gha_dir.glob("*.yml")) + list(gha_dir.glob("*.yaml")):
            content = wf.read_text(encoding="utf-8", errors="replace")
            if "pull_request_target" in content and re.search(r"actions/cache|cache@", content):
                findings.append(Finding(
                    check="CI/CD",
                    level="CRITICAL",
                    title=f"{wf.name}: pull_request_target + cache = Wave 5 entry vector",
                    detail=(
                        "This combination was used to poison the Actions cache in Wave 5.\n"
                        "Fix: use pull_request (fork-sandboxed) OR isolate cache from fork code."
                    ),
                    path=str(wf),
                ))
            if re.search(r"^permissions:\s*\n(.*\n)*?.*id-token:\s*write", content, re.MULTILINE):
                findings.append(Finding(
                    check="CI/CD",
                    level="HIGH",
                    title=f"{wf.name}: id-token: write at workflow level (must be job-scoped)",
                    detail="Grants OIDC token to all jobs. Move to the specific publish job only.",
                    path=str(wf),
                ))
            tag_pins = re.findall(r"uses:\s+[^/]+/[^@]+@v\d", content)
            if tag_pins:
                findings.append(Finding(
                    check="CI/CD",
                    level="MEDIUM",
                    title=f"{wf.name}: {len(tag_pins)} action(s) pinned by tag, not commit SHA",
                    detail="Tags can be moved. Pin to commit SHA for immutable references.",
                    path=str(wf),
                ))
    done_line("Check 6/6: GitHub Actions workflows")

    return findings

# ═══════════════════════════════════════════════════════════════════════════════
#  AUTO-FIXER  — only actions with 100% certainty and no tradeoffs
# ═══════════════════════════════════════════════════════════════════════════════

def run_autofixes(findings: List[Finding]) -> List[str]:
    fixable = [f for f in findings if f.fixable]
    applied: List[str] = []

    if not fixable:
        info("No auto-fixable items in this scan.")
        return applied

    head(f"AUTO-FIX  ({len(fixable)} item(s))")
    print()
    print(_c("  Criterion: only artefacts with no legitimate use case are removed.", "2"))
    print(_c("  Each fix is confirmed individually before execution.", "2"))
    print()

    for i, finding in enumerate(fixable, 1):
        hr("\u2500")
        print()
        bold(f"  Fix {i}/{len(fixable)}:  {finding.title}")
        dim(f"  Action : {finding.fix_label}")
        if finding.path:
            dim(f"  Target : {finding.path}")
        print()
        if confirm(f"Apply fix {i}?", default=True):
            success, msg = finding.fix_fn()
            if success:
                ok(msg)
                applied.append(f"[FIXED] {finding.title}: {msg}")
            else:
                crit(f"Fix failed: {msg}")
                applied.append(f"[FAILED] {finding.title}: {msg}")
        else:
            warn("Skipped")
            applied.append(f"[SKIPPED] {finding.title}")
        print()

    # Manual steps — require authentication
    head("MANUAL STEPS REQUIRED")
    info("These require authentication and cannot be safely automated:")
    print()
    manual = [
        ("GitHub PATs",    "github.com/settings/tokens  \u2192  Revoke all"),
        ("npm tokens",     "npm token list  \u2192  npm token revoke <id>  (for each)"),
        ("AWS keys",       "IAM \u2192 Security credentials \u2192 Access keys \u2192 Deactivate"),
        ("GCP keys",       "IAM \u2192 Service accounts \u2192 Keys \u2192 Delete all"),
        ("Azure secrets",  "App registrations \u2192 Certificates & secrets \u2192 Delete"),
        ("CI/CD secrets",  "GitHub Actions / GitLab CI / CircleCI \u2014 rotate all"),
        ("SSH keys",       "Generate new keypair; update authorized_keys on all servers"),
    ]
    for label, instruction in manual:
        print(f"  {_c(label + ':', '1;33')}  {instruction}")
    print()
    return applied

# ═══════════════════════════════════════════════════════════════════════════════
#  PROACTIVE PROTECTIONS  — disclosed tradeoffs before each action
# ═══════════════════════════════════════════════════════════════════════════════

@dataclasses.dataclass
class Protection:
    id:        str
    title:     str
    benefit:   str
    tradeoffs: List[str]
    apply_fn:  Callable
    verify_fn: Optional[Callable] = None

def _npm_config_set(key: str, value: str) -> Tuple[bool, str]:
    try:
        r = subprocess.run(["npm", "config", "set", f"{key}={value}"],
                           capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            return True, f"npm config {key}={value}"
        return False, r.stderr.strip() or "npm config set failed"
    except FileNotFoundError:
        return False, "npm not found — install Node.js first"
    except Exception as e:
        return False, str(e)

def _verify_npm_config(key: str, expected: str) -> Tuple[bool, str]:
    try:
        r = subprocess.run(["npm", "config", "get", key], capture_output=True, text=True, timeout=5)
        val = r.stdout.strip()
        return (expected in val), f"npm config {key} = {val}"
    except Exception:
        return False, "Could not verify"


def _apply_project_ignore_scripts(project_path: Path) -> Callable:
    def apply() -> Tuple[bool, str]:
        npmrc = project_path / ".npmrc"
        try:
            existing = npmrc.read_text(encoding="utf-8") if npmrc.exists() else ""
            if "ignore-scripts=true" in existing:
                return True, ".npmrc already contains ignore-scripts=true"
            with open(npmrc, "a", encoding="utf-8") as f:
                if existing and not existing.endswith("\n"):
                    f.write("\n")
                f.write("# Added by shai_hulud_guard\n")
                f.write("ignore-scripts=true\n")
            return True, f"Written to {npmrc}"
        except Exception as e:
            return False, str(e)
    return apply

def _apply_gha_pin_report(project_path: Path) -> Callable:
    def apply() -> Tuple[bool, str]:
        gha_dir = project_path / ".github" / "workflows"
        if not gha_dir.exists():
            return True, "No .github/workflows directory found"
        issues: List[str] = []
        for wf in list(gha_dir.glob("*.yml")) + list(gha_dir.glob("*.yaml")):
            content = wf.read_text(encoding="utf-8", errors="replace")
            hits = re.findall(r"(uses:\s+\S+@v[^\s]+)", content)
            for h in hits:
                issues.append(f"  {wf.name}: {h.strip()}")
        if issues:
            report_path = project_path / "shai_hulud_pin_actions.txt"
            with open(report_path, "w") as f:
                f.write("GitHub Actions requiring SHA pinning\n")
                f.write("=" * 50 + "\n\n")
                f.write("\n".join(issues))
                f.write("\n\nFor each action look up its commit SHA at:\n")
                f.write("  https://github.com/<owner>/<repo>/commits/<tag>\n")
                f.write("Then replace @vX.Y.Z with @<full-40-char-sha>\n")
            return True, f"Report: {report_path}  ({len(issues)} actions need pinning)"
        return True, "All actions already use commit SHAs"
    return apply

def _write_age_check_script(project_path: Path) -> Callable:
    """
    Write a simple age-gate wrapper script.
    npm has no native min-release-age config (verified on npm 10).
    The generated script checks publish date before calling npm install.
    """
    def apply() -> Tuple[bool, str]:
        out = project_path / "npm_safe_install.py"
        lines = [
            "#!/usr/bin/env python3",
            '"""',
            "npm_safe_install.py  —  age-gate wrapper for npm install",
            "Generated by shai_hulud_guard v2.0.0",
            "",
            "Blocks packages published less than MIN_AGE_DAYS days ago.",
            "Wave 5 spread in <6h; a 7-day gate blocks all documented Shai-Hulud waves.",
            "",
            "Usage:",
            "  python npm_safe_install.py <package[@version]>",
            "  python npm_safe_install.py lodash@4.18.1",
            "  python npm_safe_install.py @tanstack/react-router -- --save-dev",
            '"""',
            "import json, sys, subprocess, urllib.request, urllib.parse",
            "from datetime import datetime, timezone",
            "",
            "MIN_AGE_DAYS = 7  # set to 0 to disable",
            "",
            "def check_age(spec):",
            "    if spec.startswith('@'):",
            "        tail = spec[1:]",
            "        name = '@' + (tail.rsplit('@', 1)[0] if '@' in tail else tail)",
            "        ver  = tail.rsplit('@', 1)[1] if '@' in tail else None",
            "    else:",
            "        parts = spec.rsplit('@', 1)",
            "        name, ver = parts[0], (parts[1] if len(parts) > 1 else None)",
            "    try:",
            "        url = 'https://registry.npmjs.org/' + urllib.parse.quote(name, safe='@/')",
            "        req = urllib.request.Request(url, headers={'User-Agent': 'npm-age-check/1.0'})",
            "        with urllib.request.urlopen(req, timeout=10) as r:",
            "            meta = json.loads(r.read())",
            "        if not ver:",
            "            ver = meta.get('dist-tags', {}).get('latest', '')",
            "        ts = meta.get('time', {}).get(ver, '')",
            "        if not ts:",
            "            print('[age-check] No publish time found — proceeding')",
            "            return True",
            "        dt  = datetime.fromisoformat(ts.replace('Z', '+00:00'))",
            "        age = (datetime.now(timezone.utc) - dt).days",
            "        print(f'[age-check] {name}@{ver}: {age}d old', end='')",
            "        if age < MIN_AGE_DAYS:",
            "            print(f' — BLOCKED (< {MIN_AGE_DAYS}d minimum)')",
            "            print('  Edit MIN_AGE_DAYS in this script to override.')",
            "            return False",
            "        print(' — OK')",
            "        return True",
            "    except Exception as e:",
            "        print(f'[age-check] Registry lookup failed ({e}) — proceeding')",
            "        return True",
            "",
            "if __name__ == '__main__':",
            "    args = sys.argv[1:]",
            "    if not args or args[0] in ('-h', '--help'):",
            "        print(__doc__); sys.exit(0)",
            "    try:",
            "        split    = args.index('--')",
            "        pkg_args = args[:split]",
            "        npm_extra = args[split + 1:]",
            "    except ValueError:",
            "        pkg_args  = args",
            "        npm_extra = []",
            "    blocked = [p for p in pkg_args if not check_age(p)]",
            "    if blocked:",
            "        print(f'\\nBlocked {len(blocked)} package(s). Wait {MIN_AGE_DAYS}d or set MIN_AGE_DAYS=0.')",
            "        sys.exit(1)",
            "    cmd = ['npm', 'install'] + pkg_args + npm_extra",
            "    print(f'[age-check] Running: {\" \".join(cmd)}')",
            "    sys.exit(subprocess.run(cmd).returncode)",
        ]
        try:
            out.write_text("\n".join(lines) + "\n", encoding="utf-8")
            return True, f"Age-gate script written to {out}"
        except Exception as e:
            return False, str(e)
    return apply


def build_protections(project_path: Path) -> List[Protection]:
    return [
        Protection(
            id="age_check_script",
            title="Write age-gate wrapper  (npm has no native min-release-age)",
            benefit=(
                "npm 10 does not support a min-release-age config option.\n"
                "This writes npm_safe_install.py to your project — a drop-in\n"
                "wrapper that checks each package's publish date before calling\n"
                "npm install. Packages newer than 7 days are blocked.\n"
                "Usage: python npm_safe_install.py <pkg[@ver]>"
            ),
            tradeoffs=[
                "Requires using 'python npm_safe_install.py <pkg>' instead of 'npm install <pkg>'",
                "Does not enforce automatically — relies on developer discipline",
                "Adds ~1s per package for registry age lookup",
                "Set MIN_AGE_DAYS=0 inside the generated script to bypass when needed",
            ],
            apply_fn=_write_age_check_script(project_path),
        ),
        Protection(
            id="save_exact",
            title="Set save-exact=true  (global npm config)",
            benefit=(
                "npm install will record exact versions (1.2.3) instead of semver\n"
                "ranges (^1.2.3). Combined with a lock file this gives a fully\n"
                "reproducible, auditable dependency tree."
            ),
            tradeoffs=[
                "Must manually update version numbers to upgrade — more intentional (a feature in security terms)",
                "Existing projects may need a lock file refresh after enabling",
            ],
            apply_fn=lambda: _npm_config_set("save-exact", "true"),
            verify_fn=lambda: _verify_npm_config("save-exact", "true"),
        ),
        Protection(
            id="project_ignore_scripts",
            title="Add ignore-scripts=true to project .npmrc",
            benefit=(
                "Blocks all lifecycle scripts (preinstall, postinstall, prepare)\n"
                "from executing on npm install in this project. You review and\n"
                "allow scripts per-package only when verified."
            ),
            tradeoffs=[
                "Packages requiring build steps (native addons, TypeScript compile, electron) will not work",
                "Override per-package when needed: npm install <pkg> --ignore-scripts=false",
                "Does NOT block git/file transitive dependencies (they run prepare unconditionally)",
                "Some tooling (Husky git hooks, etc.) will stop working until reconfigured",
            ],
            apply_fn=_apply_project_ignore_scripts(project_path),
        ),
        Protection(
            id="gha_pin_report",
            title="Generate GitHub Actions SHA-pinning report",
            benefit=(
                "Identifies all workflow action references pinned by tag (@v4) rather\n"
                "than commit SHA. Tags can be silently moved; SHA pinning makes the\n"
                "exact code immutable. Report saved to file for your manual update."
            ),
            tradeoffs=[
                "Generates a report only — you must manually edit the YAML files",
                "SHA-pinned actions require deliberate updates to upgrade (more secure, more intentional)",
                "No automated changes are made to your workflow files",
            ],
            apply_fn=_apply_gha_pin_report(project_path),
        ),
    ]

def run_protections(project_path: Path) -> List[str]:
    protections = build_protections(project_path)
    applied: List[str] = []

    head(f"PROACTIVE PROTECTIONS  ({len(protections)} available)")
    info("Full disclosure before every action: benefit + tradeoffs + confirm.")
    print()

    for i, p in enumerate(protections, 1):
        print()
        hr("\u2500")
        bold(f"  Protection {i}/{len(protections)}:  {p.title}")
        print()
        print(_c("  BENEFIT:", "32"))
        for line in p.benefit.splitlines():
            print(f"    {line}")
        print()
        print(_c("  TRADEOFFS:", "33"))
        for t in p.tradeoffs:
            print(f"    \u26a0  {t}")
        print()

        if confirm(f"Apply protection {i}?", default=False):
            success, msg = p.apply_fn()
            if success:
                ok(msg)
                applied.append(f"[APPLIED] {p.title}: {msg}")
                if p.verify_fn:
                    time.sleep(0.4)
                    verified, vmsg = p.verify_fn()
                    (ok if verified else warn)(f"Verified: {vmsg}")
            else:
                crit(f"Failed: {msg}")
                applied.append(f"[FAILED] {p.title}: {msg}")
        else:
            info("Skipped")
            applied.append(f"[SKIPPED] {p.title}")

    return applied

# ═══════════════════════════════════════════════════════════════════════════════
#  DIAGNOSIS REPORT  — LLM-ready export
# ═══════════════════════════════════════════════════════════════════════════════

def generate_diagnosis_report(
    sysinfo:       dict,
    findings:      List[Finding],
    fixes_applied: List[str],
    protections:   List[str],
    project_path:  Path,
    all_deps:      Dict[str, str],
) -> Tuple[str, Optional[str]]:

    now = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"{REPORT_PREFIX}_{now}.txt"

    criticals = [f for f in findings if f.level == "CRITICAL"]
    highs     = [f for f in findings if f.level == "HIGH"]
    mediums   = [f for f in findings if f.level == "MEDIUM"]

    L: List[str] = []
    a = L.append

    SEP = "=" * 72
    DIV = "-" * 72

    a(SEP)
    a("SHAI-HULUD GUARD v2.0.0 — DIAGNOSIS REPORT")
    a(f"Generated : {sysinfo.get('scanned_at','unknown')}")
    a(SEP)
    a("")
    a("HOW TO USE THIS REPORT")
    a(DIV)
    a("Paste the entire contents of this file into Claude or another LLM")
    a("for personalised incident response guidance specific to your setup.")
    a("This report contains NO credential values or file contents.")
    a("")
    a("CONTEXT FOR LLM")
    a(DIV)
    a("I ran shai_hulud_guard v2.0.0 on my machine after a suspected or")
    a("potential exposure to the Shai-Hulud npm supply-chain worm (a self-")
    a("replicating worm that steals credentials via compromised npm packages).")
    a("The full findings, system info, and actions taken are below.")
    a("Please help me assess my specific risk and what I should do next.")
    a("")
    a("SYSTEM INFORMATION")
    a(DIV)
    for k, v in sysinfo.items():
        a(f"  {k:<22}: {v}")
    a("")
    a("SCAN SUMMARY")
    a(DIV)
    a(f"  Total findings : {len(findings)}")
    a(f"  CRITICAL       : {len(criticals)}")
    a(f"  HIGH           : {len(highs)}")
    a(f"  MEDIUM         : {len(mediums)}")
    a(f"  Project path   : {project_path}")
    a("")

    if findings:
        a("DETAILED FINDINGS")
        a(DIV)
        for i, f in enumerate(findings, 1):
            a(f"  [{i}] [{f.level}] [{f.check}] {f.title}")
            for line in f.detail.splitlines():
                a(f"       {line}")
            if f.path:
                a(f"       Path: {f.path}")
            a("")

    a("INSTALLED PACKAGES (from package.json)")
    a(DIV)
    if all_deps:
        for dep, ver in sorted(all_deps.items()):
            flag = "  <-- KNOWN HIGH-VALUE TARGET" if dep in HIGH_VALUE_TARGETS else ""
            a(f"  {dep:<52} {ver}{flag}")
    else:
        a("  No package.json found or no dependencies declared")
    a("")

    a("CREDENTIAL FILES PRESENT (names only — no contents)")
    a(DIV)
    for cf in CREDENTIAL_FILES:
        status = "EXISTS" if cf.exists() else "absent"
        a(f"  [{status:<8}]  {cf}")
    a("")

    if fixes_applied:
        a("AUTO-FIXES APPLIED")
        a(DIV)
        for fix in fixes_applied:
            a(f"  {fix}")
        a("")

    if protections:
        a("PROTECTIONS STATUS")
        a(DIV)
        for p in protections:
            a(f"  {p}")
        a("")

    a("QUESTIONS FOR LLM — please address these specifically")
    a(DIV)
    a("  1. How serious is my situation given these exact findings?")
    a("  2. Based on my installed packages, what is the most likely attack vector?")
    a("  3. What should I prioritize, in what order?")
    a("  4. Which credential files present the highest rotation urgency?")
    a("  5. Are any findings likely false positives vs genuine threats?")
    a("  6. Given my Node/npm versions, are there additional risks I should know?")
    a("  7. What should I check that this tool may have missed?")
    a("")
    a("REFERENCES")
    a(DIV)
    a(f"  IOC repo  : {IOC_REPO}")
    a("  CISA      : https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem")
    a("  Datadog   : https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/")
    a("  Wiz       : https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised")
    a("")
    a(SEP)
    a("END OF REPORT")
    a(SEP)

    report_text = "\n".join(L)

    saved_filename: Optional[str] = None
    try:
        with open(filename, "w", encoding="utf-8") as fh:
            fh.write(report_text)
        saved_filename = filename
    except Exception as e:
        warn(f"Could not save report: {e}")

    return report_text, saved_filename

# ═══════════════════════════════════════════════════════════════════════════════
#  PRE-INSTALL CHECKER
# ═══════════════════════════════════════════════════════════════════════════════

def _fetch_json(url: str) -> Optional[dict]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": f"shai-hulud-guard/{VERSION}"})
        with urllib.request.urlopen(req, timeout=12) as r:
            return json.loads(r.read().decode("utf-8", errors="replace"))
    except Exception as e:
        warn(f"Registry error: {e}")
        return None

def _fetch_bytes(url: str) -> Optional[bytes]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": f"shai-hulud-guard/{VERSION}"})
        with urllib.request.urlopen(req, timeout=45) as r:
            return r.read()
    except Exception as e:
        warn(f"Download error: {e}")
        return None

def run_package_check(package_spec: str) -> Tuple[int, List[Finding]]:
    """Full pre-install safety analysis. Returns (risk_score_0_to_100, findings)."""
    head(f"PRE-INSTALL CHECK: {package_spec}")
    findings: List[Finding] = []
    risk = 0

    # Parse spec
    if package_spec.startswith("@"):
        tail = package_spec[1:]
        if "@" in tail:
            name_part, ver_part = tail.rsplit("@", 1)
            pkg_name  = f"@{name_part}"
            requested = ver_part
        else:
            pkg_name  = f"@{tail}"
            requested = None
    else:
        parts = package_spec.rsplit("@", 1)
        pkg_name  = parts[0]
        requested = parts[1] if len(parts) > 1 else None

    # 1. Registry
    subh("Step 1/5 — Registry metadata")
    tick("Fetching from npm registry")
    meta = _fetch_json(f"{REGISTRY_BASE}/{urllib.parse.quote(pkg_name, safe='@/')}")
    done_line("Fetching from npm registry")
    if not meta:
        crit("Cannot reach npm registry")
        return 100, findings

    if not requested:
        requested = meta.get("dist-tags", {}).get("latest", "")
        info(f"Resolved to latest: {requested}")

    all_versions = meta.get("versions", {})

    # Known-bad removed from registry
    if requested not in all_versions:
        if pkg_name in KNOWN_BAD and requested in KNOWN_BAD[pkg_name].get("bad", []):
            crit(f"Version removed from registry — confirmed malicious")
            crit(f"DO NOT INSTALL  {pkg_name}@{requested}")
            crit(f"Waves: {', '.join(KNOWN_BAD[pkg_name]['waves'])}")
            return 100, [Finding("Known-bad", "CRITICAL",
                                 f"Confirmed removed malicious version: {pkg_name}@{requested}",
                                 "This version was actively compromised and pulled by npm.")]
        crit(f"Version '{requested}' not found in registry")
        return 0, findings

    vmeta = all_versions[requested]
    ts    = meta.get("time", {}).get(requested, "")
    if ts:
        publish_dt  = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        age_h_float = (datetime.now(timezone.utc) - publish_dt).total_seconds() / 3600
        age_d       = int(age_h_float // 24)
        ok(f"Published : {ts[:10]}  ({age_d}d {int(age_h_float%24)}h ago)")
        if age_h_float < 6:
            crit(f"Published {int(age_h_float)}h ago — CRITICAL attack window")
            risk += 40
            findings.append(Finding("Registry", "CRITICAL",
                                    f"Published only {int(age_h_float)}h ago",
                                    "Wave 5 spread in <6h. Wait 7+ days minimum."))
        elif age_h_float < 24:
            warn(f"Published {int(age_h_float)}h ago — 24h risk window")
            risk += 25
        elif age_d < 7:
            warn(f"Published {age_d}d ago — below 7-day minimum")
            risk += 10
        else:
            ok(f"Age: {age_d}d — exceeds 7-day minimum")

    maintainers = vmeta.get("maintainers", [])
    ok(f"Maintainers: {len(maintainers)}")
    if len(maintainers) == 1:
        info("Single-maintainer — one account compromise = full namespace compromise")

    # 2. Known-bad DB
    subh("Step 2/5 — Known compromised version database")
    if pkg_name in KNOWN_BAD:
        entry = KNOWN_BAD[pkg_name]
        if entry["bad"] and requested in entry["bad"]:
            crit(f"CONFIRMED COMPROMISED: {pkg_name}@{requested}")
            crit(f"DO NOT INSTALL.  Waves: {', '.join(entry['waves'])}")
            return 100, [Finding("Known-bad", "CRITICAL",
                                 f"Confirmed compromised: {pkg_name}@{requested}",
                                 f"Waves: {', '.join(entry['waves'])}")]
        warn(f"{pkg_name} is a known Shai-Hulud target — heightened scrutiny applied")
        risk += 15
        findings.append(Finding("Known-bad", "MEDIUM",
                                f"{pkg_name} repeatedly targeted",
                                f"Prior waves: {', '.join(entry.get('waves',[]))}"))
    else:
        ok("Not in known-compromised package list")

    # 3. Lifecycle scripts
    subh("Step 3/5 — Lifecycle script inspection")
    scripts = vmeta.get("scripts", {})
    hooks   = [h for h in ("preinstall", "install", "postinstall", "prepare") if h in scripts]
    if not hooks:
        ok("No lifecycle hooks declared")
    for hook in hooks:
        val  = scripts[hook]
        hits = scan_text(val)
        if hits:
            for desc, rlevel, snip in hits:
                fn = crit if rlevel == "CRITICAL" else warn
                fn(f"[{hook}] {desc}: {snip[:80]}")
                risk += 45 if rlevel == "CRITICAL" else 20 if rlevel == "HIGH" else 5
                findings.append(Finding("Scripts", rlevel,
                                        f"[{hook}]: {desc}",
                                        f"Script: {val[:200]}\nMatch: {snip}"))
        else:
            info(f"[{hook}] present: {val[:100]}")
            if hook == "preinstall":
                risk += 5

    # 4. Dependency sources
    subh("Step 4/5 — Dependency source validation")
    dep_specs: Dict[str, str] = {}
    dep_specs.update(vmeta.get("dependencies", {}))
    dep_specs.update(vmeta.get("optionalDependencies", {}))
    git_deps = {k: v for k, v in dep_specs.items()
                if any(v.startswith(p) for p in ("git+", "git://", "github:", "bitbucket:", "file:", "http://", "https://"))}
    if git_deps:
        for d, s in git_deps.items():
            warn(f"Non-registry dep (runs prepare hook): {d}: {s}")
        risk += min(len(git_deps) * 12, 30)
        findings.append(Finding("Deps", "MEDIUM",
                                f"{len(git_deps)} git/file dep(s) bypass --ignore-scripts",
                                "\n".join(f"{k}: {v}" for k, v in git_deps.items())))
    else:
        ok(f"All {len(dep_specs)} dependencies from npm registry")

    # 5. Tarball
    subh("Step 5/5 — Tarball download and deep scan")
    dist        = vmeta.get("dist", {})
    tarball_url = dist.get("tarball")
    integrity   = dist.get("integrity")
    shasum      = dist.get("shasum")

    if not tarball_url:
        warn("No tarball URL — skipping deep scan")
    else:
        info("Downloading tarball (no code execution — inspection only)...")
        t0   = time.time()
        data = _fetch_bytes(tarball_url)
        if data:
            ok(f"Downloaded {len(data)/1024:.1f} KB in {time.time()-t0:.1f}s")
            if integrity and integrity.startswith("sha512-"):
                expected = integrity[7:]
                actual   = base64.b64encode(hashlib.sha512(data).digest()).decode()
                if actual == expected:
                    ok("SHA-512 integrity verified \u2713")
                else:
                    crit("INTEGRITY MISMATCH \u2014 tarball tampered in transit or at registry")
                    risk += 100
                    findings.append(Finding("Tarball", "CRITICAL",
                                            "SHA-512 integrity check FAILED",
                                            "The downloaded tarball does not match the registry record."))
            elif shasum:
                if hashlib.sha1(data).hexdigest() == shasum:
                    ok("SHA-1 integrity verified \u2713")
                else:
                    crit("INTEGRITY MISMATCH (SHA-1)")
                    risk += 100

            if len(data) > 800_000:
                warn(f"Large tarball: {len(data)//1024} KB (Wave 5 payload was ~2.3 MB)")
                risk += 10

            tick("Scanning tarball contents")
            tb_hits = scan_tarball_bytes(data)
            done_line("Scanning tarball contents")
            if tb_hits:
                for filepath, desc, rlevel, snip in tb_hits:
                    fn = crit if rlevel == "CRITICAL" else warn
                    fn(f"{rlevel} in {filepath}: {desc}")
                    risk += 50 if rlevel == "CRITICAL" else 20 if rlevel == "HIGH" else 5
                    findings.append(Finding("Tarball", rlevel,
                                            f"In {filepath}: {desc}",
                                            f"Match: {snip[:100]}"))
            else:
                ok("No malicious patterns detected in tarball contents")

    # Risk summary
    head("PRE-INSTALL RISK REPORT")
    info(f"Package: {pkg_name}@{requested}")
    capped = min(risk, 100)
    if   capped == 0:  ok(f"Risk: 0/100 \u2014 No indicators. Proceed with caution.")
    elif capped < 15:  ok(f"Risk: {capped}/100 \u2014 Low. Manual review recommended.")
    elif capped < 40:  warn(f"Risk: {capped}/100 \u2014 Moderate. Verify independently.")
    elif capped < 70:  warn(f"Risk: {capped}/100 \u2014 High. Investigate before installing.")
    else:              crit(f"Risk: {capped}/100 \u2014 CRITICAL. Do not install.")

    if findings:
        print()
        info("Findings:")
        for f in findings:
            fn = crit if f.level == "CRITICAL" else warn if f.level in ("HIGH", "MEDIUM") else info
            fn(f"  [{f.level}] {f.title}")

    print()
    info("Safe install workflow if proceeding:")
    pkg_clean = pkg_name.lstrip("@").replace("/", "/")
    print(f"""
    # Install without executing any lifecycle scripts
    npm install {pkg_name}@{requested} --ignore-scripts

    # Inspect declared scripts
    cat node_modules/{pkg_clean}/package.json | \\
      python3 -c "import sys,json; d=json.load(sys.stdin); print(json.dumps(d.get('scripts',{{}}),indent=2))"

    # Search for known payload filenames
    find node_modules/{pkg_name} \\
      -name "router_init.js" -o -name "setup_bun.js" -o -name "bun_environment.js"
    """)

    dim("Limitations: novel obfuscation, runtime-fetched payloads, and zero-day variants")
    dim(f"will not be caught. Cross-check: {IOC_REPO}")
    return capped, findings

# ═══════════════════════════════════════════════════════════════════════════════
#  INCIDENT GUIDE
# ═══════════════════════════════════════════════════════════════════════════════

def show_incident_guide():
    head("INCIDENT RESPONSE GUIDE")
    info("Sourced from: CISA advisory, Wiz, Datadog, StepSecurity postmortems")
    steps = [
        ("STEP 1 \u2014 STOP", [
            "DO NOT revoke tokens yet.",
            "gh-token-monitor polls GitHub every 60s and triggers rm -rf ~/ on revocation.",
            "The daemon self-destructs after 24 hours \u2014 act within that window.",
        ]),
        ("STEP 2 \u2014 ISOLATE", [
            "Pull ethernet cable or disable Wi-Fi immediately.",
            "For CI runner: stop the runner service (not cancel the job).",
            "Do not log in to any account from the infected machine.",
        ]),
        ("STEP 3 \u2014 IMAGE (forensics)", [
            "Linux:  sudo dd if=/dev/sda bs=4M | gzip > backup_$(date +%Y%m%d).img.gz",
            "macOS:  Disk Utility \u2192 Image \u2192 Device Image before cleanup.",
            "CI/CD:  VM snapshot if the runner is virtualised.",
        ]),
        ("STEP 4 \u2014 REMOVE DAEMON", [
            "Linux:  systemctl --user stop gh-token-monitor",
            "        rm ~/.config/systemd/user/gh-token-monitor.service",
            "        systemctl --user daemon-reload",
            "macOS:  launchctl unload ~/Library/LaunchAgents/com.user.gh-token-monitor.plist",
            "        rm ~/Library/LaunchAgents/com.user.gh-token-monitor.plist",
            "Win:    schtasks /query | findstr gh-token",
            "        schtasks /delete /tn <name> /f",
        ]),
        ("STEP 5 \u2014 ROTATE CREDENTIALS (daemon confirmed removed)", [
            "GitHub PATs:  github.com/settings/tokens \u2192 Revoke all",
            "npm tokens:   npm token list \u2192 npm token revoke <id>",
            "AWS:          IAM \u2192 Access keys \u2192 Deactivate + Delete",
            "GCP:          IAM \u2192 Service accounts \u2192 Keys \u2192 Delete all",
            "Azure:        App registrations \u2192 Secrets \u2192 Delete all",
            "SSH:          Generate new keypair, update authorized_keys everywhere",
        ]),
        ("STEP 6 \u2014 AUDIT PUBLISH HISTORY", [
            "npm:    npm access ls-packages <username>",
            "GitHub: search repos for description containing 'Shai-Hulud'",
            "If your packages were backdoored: notify downstream users immediately.",
        ]),
        ("STEP 7 \u2014 REBUILD", [
            "Wipe and reinstall OS \u2014 do not clean in place.",
            "Rebuild CI runners from a verified base image.",
            "Generate all new secrets from a clean machine.",
        ]),
        ("STEP 8 \u2014 REPORT", [
            "npm:    security@npmjs.com",
            "GitHub: github.com/contact/security",
            "CISA:   cisa.gov/reporting",
        ]),
    ]
    for title, items in steps:
        print()
        print(_c(f"  {title}", "1;33"))
        for item in items:
            indent = "      " if item.startswith("    ") else "    "
            print(f"{indent}\u2022 {item.strip()}")

# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN INTERACTIVE FLOW
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description=f"shai_hulud_guard v{VERSION} \u2014 Shai-Hulud npm worm scanner + fixer",
    )
    parser.add_argument("--path", default=".",
                        help="Project directory to scan (default: current directory)")
    parser.add_argument("--check", metavar="PKG[@VER]",
                        help="Pre-install check only (non-interactive)")
    parser.add_argument("--version", action="version", version=f"shai_hulud_guard {VERSION}")
    args = parser.parse_args()

    # Non-interactive mode: --check
    if args.check:
        banner()
        run_package_check(args.check)
        sys.exit(0)

    # Python version gate
    if sys.version_info < (3, 8):
        print(f"Python 3.8+ required. Found: {platform.python_version()}")
        sys.exit(1)

    project_path = Path(args.path).resolve()
    sysinfo      = collect_system_info()

    banner()
    info(f"Project path : {project_path}")
    info(f"System       : {sysinfo['os']}")
    info(f"Python       : {sysinfo['python']}")
    info(f"Node.js      : {sysinfo['node_version']}")
    info(f"npm          : {sysinfo['npm_version']}")

    # ── MAIN LOOP ─────────────────────────────────────────────────────────────
    while True:
        top_choice = menu("What would you like to do?", [
            ("1", "Full scan \u2014 detect infection indicators in this project and machine"),
            ("2", "Pre-install check \u2014 analyse an npm package before installing"),
            ("3", "Incident response guide"),
            ("Q", "Quit"),
        ])

        if top_choice == "Q":
            print(); info("Exiting."); sys.exit(0)

        if top_choice == "2":
            pkg = input(_c("  Package spec (e.g. @tanstack/react-router@1.2.3): ", "33")).strip()
            if pkg:
                run_package_check(pkg)
            pause()
            banner()
            info(f"Project: {project_path}")
            continue

        if top_choice == "3":
            show_incident_guide()
            pause()
            banner()
            info(f"Project: {project_path}")
            continue

        # ── FULL SCAN ─────────────────────────────────────────────────────────
        head("SCANNING")
        info(f"Scanning: {project_path}")
        print()

        findings = run_scan(project_path)

        # Collect deps for report
        all_deps: Dict[str, str] = {}
        pkg_json = project_path / "package.json"
        if pkg_json.exists():
            try:
                pdata = json.loads(pkg_json.read_text(encoding="utf-8", errors="replace"))
                for s in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                    all_deps.update(pdata.get(s, {}))
            except Exception:
                pass

        # Summary
        print()
        criticals = [f for f in findings if f.level == "CRITICAL"]
        highs     = [f for f in findings if f.level == "HIGH"]
        mediums   = [f for f in findings if f.level == "MEDIUM"]
        if not findings:
            ok("SCAN COMPLETE \u2014 No infection indicators found")
            ok("All 6 checks passed")
        elif criticals:
            crit(f"SCAN COMPLETE \u2014 {len(findings)} finding(s):"
                 f"  {len(criticals)} CRITICAL  {len(highs)} HIGH  {len(mediums)} MEDIUM")
        else:
            warn(f"SCAN COMPLETE \u2014 {len(findings)} finding(s):"
                 f"  {len(highs)} HIGH  {len(mediums)} MEDIUM")

        fixes_applied:   List[str] = []
        protections_log: List[str] = []
        has_fixable = any(f.fixable for f in findings)

        # ── POST-SCAN MENU ────────────────────────────────────────────────────
        while True:
            opts: List[Tuple[str, str]] = []
            if findings:
                opts.append(("D", "View detailed findings"))
            if has_fixable:
                opts.append(("F", "Auto-fix safe items  (100% certainty, no tradeoffs)"))
            opts.append(("P", "Set up proactive protections  (disclosed tradeoffs)"))
            if findings:
                opts.append(("R", "Generate diagnosis report  (paste into LLM)"))
            opts.append(("C", "Pre-install check for a specific package"))
            opts.append(("I", "Incident response guide"))
            opts.append(("M", "Return to main menu"))

            action = menu("Next step:", opts)

            if action == "D":
                head("FINDINGS DETAIL")
                for i, f in enumerate(findings, 1):
                    print()
                    print(_c(f"  [{i}/{len(findings)}]", "2"))
                    f.display()
                pause()

            elif action == "F":
                fixes_applied = run_autofixes(findings)
                # Refresh fixable state after applying
                has_fixable = any(
                    f.fixable and f"[FIXED] {f.title}" not in " ".join(fixes_applied)
                    for f in findings
                )
                pause()

            elif action == "P":
                protections_log = run_protections(project_path)
                pause()

            elif action == "R":
                head("GENERATING DIAGNOSIS REPORT")
                report_text, filename = generate_diagnosis_report(
                    sysinfo, findings, fixes_applied, protections_log, project_path, all_deps
                )
                print()
                if filename:
                    ok(f"Report saved: {filename}")
                    info("Open the file and paste its entire contents into Claude or another LLM.")
                    info("The report contains NO credential values or file contents.")
                else:
                    warn("Could not save to file")

                if confirm("Display report on screen now?", default=False):
                    print()
                    hr()
                    print(report_text)
                    hr()
                pause()

            elif action == "C":
                pkg = input(_c("  Package to check: ", "33")).strip()
                if pkg:
                    run_package_check(pkg)
                pause()

            elif action == "I":
                show_incident_guide()
                pause()

            elif action == "M":
                banner()
                info(f"Project: {project_path}")
                break

# ═══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        info("Interrupted.")
        sys.exit(0)
