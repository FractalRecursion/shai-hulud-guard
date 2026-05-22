"""
Structural tests for the KNOWN_BAD / HIGH_VALUE_TARGETS / DAEMON_PATHS /
CREDENTIAL_FILES / MALICIOUS_FILENAMES constants (canonical v2.4 module).

These are not behaviour tests — they guard the shape of the data so a typo or
restructure during an IOC update doesn't silently break the consumers
(run_scan, run_check, run_pypi_check, the diagnosis report, the verdict tiers).
"""
from __future__ import annotations

# ─── MALICIOUS_FILENAMES ──────────────────────────────────────────────────────

def test_malicious_filenames_is_a_set(guard):
    assert isinstance(guard.MALICIOUS_FILENAMES, set)
    assert all(isinstance(x, str) for x in guard.MALICIOUS_FILENAMES)
    assert "router_init.js" in guard.MALICIOUS_FILENAMES


def test_core_malicious_filenames_present(guard):
    """The canonical worm payload filenames must be present."""
    core = {"router_init.js", "setup_bun.js", "bun_environment.js", "setup.mjs"}
    assert core.issubset(guard.MALICIOUS_FILENAMES)


# ─── KNOWN_BAD ────────────────────────────────────────────────────────────────

def test_known_bad_shape(guard):
    """
    Every KNOWN_BAD entry has the required keys (bad, waves) and the optional
    advisories key (added v2.4 for GHSA/CVE/OSV cross-reference). Extra keys
    beyond {bad, waves, advisories} are a likely typo and should fail.
    """
    allowed_keys = {"bad", "waves", "advisories"}
    required_keys = {"bad", "waves"}
    assert isinstance(guard.KNOWN_BAD, dict)
    for pkg, entry in guard.KNOWN_BAD.items():
        assert isinstance(pkg, str)
        assert isinstance(entry, dict)
        keys = set(entry.keys())
        assert required_keys.issubset(keys), f"{pkg}: missing required keys: {required_keys - keys}"
        assert keys.issubset(allowed_keys), f"{pkg}: unexpected keys: {keys - allowed_keys}"
        assert isinstance(entry["bad"], list)
        assert isinstance(entry["waves"], list)
        assert all(isinstance(v, str) for v in entry["bad"])
        assert all(isinstance(w, str) for w in entry["waves"])
        if "advisories" in entry:
            assert isinstance(entry["advisories"], list)
            assert all(isinstance(a, str) for a in entry["advisories"])


def test_known_bad_contains_confirmed_wave5_entries(guard):
    """Confirmed-malicious versions from public post-mortems must be present."""
    assert "1.169.5" in guard.KNOWN_BAD["@tanstack/react-router"]["bad"]
    assert "1.169.5" in guard.KNOWN_BAD["@tanstack/router"]["bad"]
    assert "7.0.4" in guard.KNOWN_BAD["intercom-client"]["bad"]


# ─── HIGH_VALUE_TARGETS ──────────────────────────────────────────────────────

def test_high_value_targets_superset_of_known_bad(guard):
    """HIGH_VALUE_TARGETS must contain every KNOWN_BAD package."""
    assert set(guard.KNOWN_BAD.keys()).issubset(guard.HIGH_VALUE_TARGETS)


# ─── DAEMON_PATHS — regression guard for CLAUDE.md §4.5 ──────────────────────

def test_daemon_paths_windows_is_empty(guard):
    """Per CLAUDE.md §4.5: Windows daemon path is intentionally empty until a
    path is publicly documented (detection is via check_windows_persistence()).
    A 'helpful' guess here breaks the no-false-positive invariant."""
    assert guard.DAEMON_PATHS["windows"] == []


def test_daemon_paths_has_three_platforms(guard):
    assert set(guard.DAEMON_PATHS.keys()) == {"linux", "darwin", "windows"}


def test_daemon_paths_linux_and_darwin_nonempty(guard):
    assert len(guard.DAEMON_PATHS["linux"]) >= 1
    assert len(guard.DAEMON_PATHS["darwin"]) >= 1


# ─── CREDENTIAL_FILES ────────────────────────────────────────────────────────

def test_credential_files_present(guard):
    names = {p.name for p in guard.CREDENTIAL_FILES}
    # Core set that the worm is documented to sweep:
    assert {".npmrc", "credentials", "id_rsa", "id_ed25519"}.issubset(names)
