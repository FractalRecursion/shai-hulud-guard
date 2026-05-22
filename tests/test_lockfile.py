"""
Tests for _lockfile_packages — package-lock.json v1/v2/v3 normalisation.

v1: nested {"dependencies": {name: {version, dependencies: {...}}}}
v2/v3: flat {"packages": {"node_modules/name": {...}, "": {root}}}
Both must normalise to {name: meta} so the lockfile auditor can iterate uniformly.
"""
from __future__ import annotations


def test_v1_nested_dependencies_flattened(guard):
    lock = {
        "lockfileVersion": 1,
        "dependencies": {
            "lodash": {"version": "4.17.21"},
            "express": {
                "version": "4.18.2",
                "dependencies": {
                    "accepts": {"version": "1.3.8"},
                },
            },
        },
    }
    pkgs = guard._lockfile_packages(lock)
    assert "lodash" in pkgs
    assert "express" in pkgs
    assert "accepts" in pkgs, "nested v1 dependency was not flattened"
    assert pkgs["accepts"]["version"] == "1.3.8"


def test_v2_packages_node_modules_prefix_stripped(guard):
    lock = {
        "lockfileVersion": 2,
        "packages": {
            "": {"name": "myapp", "version": "1.0.0"},
            "node_modules/lodash": {"version": "4.17.21"},
            "node_modules/express": {"version": "4.18.2"},
            "node_modules/express/node_modules/accepts": {"version": "1.3.8"},
        },
    }
    pkgs = guard._lockfile_packages(lock)
    assert "lodash" in pkgs
    assert "express" in pkgs
    # Only the LEADING node_modules/ prefix is stripped (top-level packages are
    # keyed by bare name). Deeply-nested entries retain their nested path —
    # they are still scanned, just keyed distinctly.
    assert "express/node_modules/accepts" in pkgs
    assert pkgs["express/node_modules/accepts"]["version"] == "1.3.8"
    # the root "" entry must NOT appear as a package
    assert "" not in pkgs


def test_v3_same_as_v2(guard):
    lock = {
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "root"},
            "node_modules/chalk": {"version": "5.3.0"},
        },
    }
    pkgs = guard._lockfile_packages(lock)
    assert "chalk" in pkgs
    assert pkgs["chalk"]["version"] == "5.3.0"


def test_empty_lock_returns_empty(guard):
    assert guard._lockfile_packages({}) == {}
    assert guard._lockfile_packages({"lockfileVersion": 2, "packages": {}}) == {}
