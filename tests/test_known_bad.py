"""
Structural tests for the KNOWN_BAD / HIGH_VALUE_TARGETS / DAEMON_PATHS /
CREDENTIAL_FILES / MALICIOUS_FILENAMES constants.

These are not behaviour tests — they guard the shape of the data so a typo or
restructure during an IOC update doesn't silently break the consumers
(run_scan, run_package_check, the diagnosis report, the verdict tiers).
"""
from __future__ import annotations


# ─── MALICIOUS_FILENAMES ──────────────────────────────────────────────────────

def test_malicious_filenames_is_a_set_v1(v1):
    assert isinstance(v1.MALICIOUS_FILENAMES, set)
    assert all(isinstance(x, str) for x in v1.MALICIOUS_FILENAMES)
    assert "router_init.js" in v1.MALICIOUS_FILENAMES


def test_malicious_filenames_is_a_set_v2(v2):
    assert isinstance(v2.MALICIOUS_FILENAMES, set)
    assert "router_init.js" in v2.MALICIOUS_FILENAMES


def test_v1_v2_share_core_malicious_filenames(v1, v2):
    """Both versions must agree on the canonical worm payload filenames."""
    core = {"router_init.js", "setup_bun.js", "bun_environment.js", "setup.mjs"}
    assert core.issubset(v1.MALICIOUS_FILENAMES)
    assert core.issubset(v2.MALICIOUS_FILENAMES)


# ─── KNOWN_BAD ────────────────────────────────────────────────────────────────

def _assert_known_bad_shape(module):
    assert isinstance(module.KNOWN_BAD, dict)
    for pkg, entry in module.KNOWN_BAD.items():
        assert isinstance(pkg, str)
        assert isinstance(entry, dict)
        assert set(entry.keys()) == {"bad", "waves"}, (
            f"{pkg}: extra/missing keys in KNOWN_BAD entry: {set(entry.keys())}"
        )
        assert isinstance(entry["bad"], list)
        assert isinstance(entry["waves"], list)
        assert all(isinstance(v, str) for v in entry["bad"])
        assert all(isinstance(w, str) for w in entry["waves"])


def test_known_bad_shape_v1(v1):
    _assert_known_bad_shape(v1)


def test_known_bad_shape_v2(v2):
    _assert_known_bad_shape(v2)


def test_known_bad_contains_confirmed_wave5_entries_v1(v1):
    """Confirmed-malicious versions from public post-mortems must be present."""
    assert "1.169.5" in v1.KNOWN_BAD["@tanstack/react-router"]["bad"]
    assert "1.169.5" in v1.KNOWN_BAD["@tanstack/router"]["bad"]


def test_known_bad_contains_confirmed_wave5_entries_v2(v2):
    assert "1.169.5" in v2.KNOWN_BAD["@tanstack/react-router"]["bad"]
    assert "1.169.5" in v2.KNOWN_BAD["@tanstack/router"]["bad"]


# ─── HIGH_VALUE_TARGETS ──────────────────────────────────────────────────────

def test_high_value_targets_superset_of_known_bad_v1(v1):
    """HIGH_VALUE_TARGETS must contain every KNOWN_BAD package."""
    assert set(v1.KNOWN_BAD.keys()).issubset(v1.HIGH_VALUE_TARGETS)


def test_high_value_targets_superset_of_known_bad_v2(v2):
    assert set(v2.KNOWN_BAD.keys()).issubset(v2.HIGH_VALUE_TARGETS)


# ─── DAEMON_PATHS — regression guard for CLAUDE.md §4.5 ──────────────────────

def test_daemon_paths_windows_is_empty_v1(v1):
    """Per CLAUDE.md §4.5: Windows daemon path is intentionally empty
    until a path is publicly documented. A 'helpful' guess here breaks
    the no-false-positive invariant."""
    assert v1.DAEMON_PATHS["windows"] == []


def test_daemon_paths_windows_is_empty_v2(v2):
    assert v2.DAEMON_PATHS["windows"] == []


def test_daemon_paths_has_three_platforms_v1(v1):
    assert set(v1.DAEMON_PATHS.keys()) == {"linux", "darwin", "windows"}


def test_daemon_paths_has_three_platforms_v2(v2):
    assert set(v2.DAEMON_PATHS.keys()) == {"linux", "darwin", "windows"}


def test_daemon_paths_linux_and_darwin_nonempty_v1(v1):
    assert len(v1.DAEMON_PATHS["linux"]) >= 1
    assert len(v1.DAEMON_PATHS["darwin"]) >= 1


def test_daemon_paths_linux_and_darwin_nonempty_v2(v2):
    assert len(v2.DAEMON_PATHS["linux"]) >= 1
    assert len(v2.DAEMON_PATHS["darwin"]) >= 1


# ─── CREDENTIAL_FILES ────────────────────────────────────────────────────────

def test_credential_files_present_v1(v1):
    names = {p.name for p in v1.CREDENTIAL_FILES}
    # Core set that the worm is documented to sweep:
    assert {".npmrc", "credentials", "id_rsa", "id_ed25519"}.issubset(names)


def test_credential_files_present_v2(v2):
    names = {p.name for p in v2.CREDENTIAL_FILES}
    assert {".npmrc", "credentials", "id_rsa", "id_ed25519"}.issubset(names)
