"""
Tests for _distrib_noise_filter — the per-path risk demotion logic.

Regression guards for the calibration fixes (Pillow, pymongo, virtualenv):
  - Install-time files keep their risk verbatim.
  - Non-executing dirs (tests + CI) demote CRITICAL→MEDIUM, suppress the rest.
  - CRITICAL in real source passes through.
  - Soft-noise dirs (docs, vendored) demote one level; CRITICAL stays.
"""
from __future__ import annotations

import pytest


# ─── Install-time files keep verbatim risk ────────────────────────────────────

@pytest.mark.parametrize("setup_file", [
    "setup.py", "package.json", "preinstall.js", "postinstall.js",
])
@pytest.mark.parametrize("risk", ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
def test_setup_files_keep_risk(guard, setup_file, risk):
    assert guard._distrib_noise_filter(f"pkg/{setup_file}", risk) == risk


# ─── Non-executing dirs: CRITICAL→MEDIUM, lower→LOW ──────────────────────────

@pytest.mark.parametrize("path", [
    "pkg/tests/test_x.py",
    "pkg/Tests/test_imagegrab.py",     # Pillow (capital T, lowercased internally)
    "pkg/.evergreen/scripts/run.py",   # pymongo CI
    "pkg/.github/workflows/ci.yml",
    "pkg/tests/unit/test_creator.py",  # virtualenv
])
def test_noexec_dirs_demote_critical_to_medium(guard, path):
    assert guard._distrib_noise_filter(path, "CRITICAL") == "MEDIUM", (
        f"{path}: CRITICAL should demote to MEDIUM (non-executing dir)"
    )


@pytest.mark.parametrize("path", [
    "pkg/tests/test_x.py",
    "pkg/.evergreen/scripts/run.py",
])
@pytest.mark.parametrize("risk", ["HIGH", "MEDIUM", "LOW"])
def test_noexec_dirs_suppress_below_critical(guard, path, risk):
    assert guard._distrib_noise_filter(path, risk) == "LOW", (
        f"{path} @ {risk}: non-CRITICAL in non-exec dir should suppress to LOW"
    )


# ─── CRITICAL in real source passes through ──────────────────────────────────

@pytest.mark.parametrize("path", [
    "pkg/lib/index.js",
    "pkg/src/loader.py",
    "pkg/dist/main.js",
])
def test_real_source_critical_passes_through(guard, path):
    assert guard._distrib_noise_filter(path, "CRITICAL") == "CRITICAL"


# ─── Soft-noise dirs demote one level; CRITICAL stays ────────────────────────

def test_soft_noise_high_demotes_to_medium(guard):
    assert guard._distrib_noise_filter("pkg/docs/example.js", "HIGH") == "MEDIUM"


def test_soft_noise_medium_demotes_to_low(guard):
    assert guard._distrib_noise_filter("pkg/docs/example.js", "MEDIUM") == "LOW"


def test_soft_noise_critical_stays(guard):
    """Vendored code CAN execute, so CRITICAL is not demoted in soft-noise dirs."""
    assert guard._distrib_noise_filter("pkg/vendor/thing.js", "CRITICAL") == "CRITICAL"
