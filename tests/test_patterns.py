"""
Tests for the pattern engine (scan_text) in both v1.1 and v2.0.

We test:
  - A clean string returns no findings.
  - Every entry in MALICIOUS_PATTERNS triggers itself (catches typos in the
    regex that would silently never match).
  - The dedup-by-(desc, risk) rule works.
  - The ASCII-only unicode-escape pattern doesn't fire on legitimate i18n.
  - The risk_level strings are exactly the four canonical values.
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
def test_clean_text_returns_no_findings_v1(v1, clean_text):
    assert v1.scan_text(clean_text) == []


@pytest.mark.parametrize("clean_text", [
    "",
    "function add(a, b) { return a + b; }",
    "// just a comment\nmodule.exports = require('lodash');",
])
def test_clean_text_returns_no_findings_v2(v2, clean_text):
    assert v2.scan_text(clean_text) == []


# ─── Risk-level vocabulary is exactly the canonical set ───────────────────────

def test_v1_risk_levels_are_canonical(v1):
    levels = {risk for _, _, risk in v1.MALICIOUS_PATTERNS}
    assert levels.issubset(CANONICAL_LEVELS), (
        f"Unexpected risk-level string(s): {levels - CANONICAL_LEVELS}. "
        "Allowed: CRITICAL/HIGH/MEDIUM/LOW (see CLAUDE.md §4.2)."
    )


def test_v2_risk_levels_are_canonical(v2):
    levels = {risk for _, _, risk in v2.MALICIOUS_PATTERNS}
    assert levels.issubset(CANONICAL_LEVELS), (
        f"Unexpected risk-level string(s): {levels - CANONICAL_LEVELS}."
    )


# ─── Every pattern can detect its own marker ──────────────────────────────────
#
# Strategy: for each (regex, desc, risk), construct a string that the regex
# can match. We can't synthesize a guaranteed-match for arbitrary regex, so
# we use a known matching exemplar per pattern. If a pattern is rewritten,
# the exemplar list below must be updated alongside it.

EXEMPLARS = {
    "Worm identity string":                        "// Shai-Hulud was here",
    "Worm campaign tag":                           "label = 'Here We Go Again'",
    "Known threat actor":                          "actor = 'TeamPCP'",
    "Known threat actor marker":                   "actor = 'TeamPCP'",
    "Daemon name":                                 "service: gh-token-monitor",
    "Persistent token-monitor daemon name":        "service: gh-token-monitor",
    "Worm repo tag":                               "A Mini Shai-Hulud has Appeared",
    "Worm repo description tag":                   "A Mini Shai-Hulud has Appeared",
    "Home-dir wipe (Linux/macOS)":                 "exec('rm -rf ~')",
    "Linux/macOS home-directory wipe":             "exec('rm -rf ~')",
    "Home-dir wipe (Windows)":                     "rmdir /s /q %USERPROFILE%\\stuff",
    "Windows home-directory wipe":                 "rmdir /s /q %USERPROFILE%\\stuff",
    "C2 typosquat domain":                         "url = 'https://git-tanstack.com/x'",
    "Known C2 typosquat domain":                   "url = 'https://git-tanstack.com/x'",
    "Known exfil endpoint":                        "webhook.site/12345678-90ab-cdef-1234-567890abcdef",
    "Known exfiltration endpoint (webhook.site)":  "webhook.site/12345678-90ab-cdef-1234-567890abcdef",
    "Session network C2 channel":                  "host = 'getsession.org'",
    "Session network (C2 exfiltration channel)":   "host = 'getsession.org'",
    "GitHub PAT literal":                          "TOKEN = 'ghp_" + "a" * 36 + "'",
    "GitHub PAT literal in code":                  "TOKEN = 'ghp_" + "a" * 36 + "'",
    "GitHub OAuth token literal":                  "TOKEN = 'gho_" + "a" * 36 + "'",
    "npm token literal":                           "TOKEN = 'npm_" + "a" * 36 + "'",
    "GCP credential file access":                  "read('application_default_credentials.json')",
    "AWS credential access":                       "AWS_SECRET_ACCESS_KEY=abc",
    "Azure credential access":                     "AZURE_CLIENT_SECRET=xyz",
    "SSH private key access":                      "open('~/.ssh/id_rsa')",
    ".npmrc credential file access":               "open('~/.npmrc')",
    "Bun installer in lifecycle script":           "curl https://bun.sh/install | bash",
    "Bun runtime installer in lifecycle script":   "curl https://bun.sh/install | bash",
    "Bun payload execution":                       "spawn('bun', ['run', './x.js'])",
    "Bun used to execute payload":                 "spawn('bun', ['run', './x.js'])",
    "Runner memory extraction":                    "open('/proc/1234/mem')",
    "CI runner memory extraction":                 "open('/proc/1234/mem')",
    "GitHub OIDC token ENV access":                "env.ACTIONS_ID_TOKEN_REQUEST_URL",
    "GitHub OIDC token ENV var access":            "env.ACTIONS_ID_TOKEN_REQUEST_URL",
    "OIDC id-token scope in config":               "id-token: write",
    "macOS LaunchAgent persistence":                "~/Library/LaunchAgents/com.user.gh-token-monitor.plist",
    "Linux systemd persistence":                   "~/.config/systemd/user/foo.service",
    "Linux systemd user service persistence":      "~/.config/systemd/user/foo.service",
    "Windows Task Scheduler persistence":          "SCHTASKS /create /tn evil",
    "eval of decoded content":                     "eval(atob('cGF5bG9hZA=='))",
    "Base64 decode in script":                     "Buffer.from(s, 'base64')",
    "Base64 decode pattern (obfuscation signal)":  "Buffer.from(s, 'base64')",
    "ASCII chars encoded as \\u escapes":          "x = '\\u0065\\u0076\\u0061\\u006C'",
    "ASCII chars encoded as \\u escapes (obfuscation)":
                                                    "x = '\\u0065\\u0076\\u0061\\u006C'",
    "GitHub API repo creation (credential dump)":  "fetch('https://api.github.com/user/repos')",
    "Authenticated GitHub API call in script":     "fetch('github.com/x/y/repos', {method: 'POST', headers: {Authorization: 'token xx'}})",
    "pull_request_target (cache poison vector)":   "on: pull_request_target",
    "pull_request_target trigger (cache poison vector)":
                                                    "on: pull_request_target",
    "Cache restore with broad key (potential poison)":
                                                    "actions/cache restore-keys = deps-",
}


def _check_self_detection(module, exemplars):
    """Each pattern in module.MALICIOUS_PATTERNS detects its own exemplar."""
    missing = []
    not_found = []
    for pattern, desc, risk in module.MALICIOUS_PATTERNS:
        exemplar = exemplars.get(desc)
        if exemplar is None:
            missing.append(desc)
            continue
        if not re.search(pattern, exemplar, re.IGNORECASE):
            not_found.append((desc, pattern, exemplar))
    return missing, not_found


def test_v1_each_pattern_has_an_exemplar(v1):
    missing, _ = _check_self_detection(v1, EXEMPLARS)
    assert not missing, (
        "These v1.1 pattern descriptions have no exemplar in tests/test_patterns.py — "
        "add one when adding a pattern:\n  " + "\n  ".join(missing)
    )


def test_v2_each_pattern_has_an_exemplar(v2):
    missing, _ = _check_self_detection(v2, EXEMPLARS)
    assert not missing, (
        "These v2.0 pattern descriptions have no exemplar in tests/test_patterns.py:\n  "
        + "\n  ".join(missing)
    )


def test_v1_every_pattern_matches_its_exemplar(v1):
    _, not_found = _check_self_detection(v1, EXEMPLARS)
    assert not not_found, (
        "Some v1.1 patterns failed to match their own exemplar — regex typo?\n"
        + "\n".join(f"  desc={d!r} pattern={p!r} exemplar={e!r}" for d, p, e in not_found)
    )


def test_v2_every_pattern_matches_its_exemplar(v2):
    _, not_found = _check_self_detection(v2, EXEMPLARS)
    assert not not_found, (
        "Some v2.0 patterns failed to match their own exemplar — regex typo?\n"
        + "\n".join(f"  desc={d!r} pattern={p!r} exemplar={e!r}" for d, p, e in not_found)
    )


# ─── Dedup-by-(desc, risk) ────────────────────────────────────────────────────

def test_dedup_by_desc_risk_v1(v1):
    """Multiple matches of the same pattern collapse to one finding."""
    s = "Shai-Hulud\nShai-Hulud\nShai-Hulud"  # three occurrences
    hits = v1.scan_text(s)
    worm_hits = [h for h in hits if "Worm identity" in h[0]]
    assert len(worm_hits) == 1


def test_dedup_by_desc_risk_v2(v2):
    s = "Shai-Hulud\nShai-Hulud"
    hits = v2.scan_text(s)
    worm_hits = [h for h in hits if "Worm identity" in h[0]]
    assert len(worm_hits) == 1


# ─── ASCII-scoped unicode-escape pattern: regression guard for CLAUDE.md §5.6 ─

def test_ascii_unicode_escapes_match_v1(v1):
    """ASCII-range \\u escapes (worm obfuscation pattern) ARE detected."""
    ascii_obf = "var x = '\\u0065\\u0076\\u0061\\u006C';"  # encodes "eval"
    descs = [d for d, _, _ in v1.scan_text(ascii_obf)]
    assert any("\\u escapes" in d for d in descs)


def test_ascii_unicode_escapes_match_v2(v2):
    ascii_obf = "var x = '\\u0065\\u0076\\u0061\\u006C';"
    descs = [d for d, _, _ in v2.scan_text(ascii_obf)]
    assert any("\\u escapes" in d for d in descs)


def test_high_codepoint_unicode_escapes_DO_NOT_match_v1(v1):
    """Legitimate i18n high-codepoint escapes are NOT flagged."""
    i18n = "var t = '\\u01A0\\u01A1\\u01B2\\u01C3\\u01D4\\u01E5';"
    descs = [d for d, _, _ in v1.scan_text(i18n)]
    assert not any("\\u escapes" in d for d in descs), (
        f"High-codepoint escapes triggered the unicode-escape pattern — "
        f"this regresses CLAUDE.md §5.6. Hits: {descs}"
    )


def test_high_codepoint_unicode_escapes_DO_NOT_match_v2(v2):
    i18n = "var t = '\\u01A0\\u01A1\\u01B2\\u01C3\\u01D4\\u01E5';"
    descs = [d for d, _, _ in v2.scan_text(i18n)]
    assert not any("\\u escapes" in d for d in descs)
