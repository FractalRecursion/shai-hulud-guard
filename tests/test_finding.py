"""
Tests for the v2.4 Finding dataclass and _wrap_finding normaliser.

Finding is the structured output type used by --json and --diagnose. It must:
  - default its optional fields sensibly,
  - iterate as (level, title) for backward-compat with legacy tuple unpacking,
  - serialise to a dict with the exact JSON-schema keys,
  - round-trip legacy 2-tuples through _wrap_finding.
"""
from __future__ import annotations

import pytest

ALL_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SCHEMA_KEYS = {"level", "title", "detail", "path", "score_contribution", "advisories"}


def test_finding_defaults(guard):
    f = guard.Finding(level="HIGH", title="t")
    assert f.level == "HIGH"
    assert f.title == "t"
    assert f.detail == ""
    assert f.path is None
    assert f.score_contribution == 0
    assert f.advisories == []


def test_finding_is_iterable_as_level_title(guard):
    """Backward compat: legacy `for level, msg in findings:` must still work."""
    f = guard.Finding(level="CRITICAL", title="boom")
    level, title = f
    assert level == "CRITICAL"
    assert title == "boom"


@pytest.mark.parametrize("level", ALL_LEVELS)
def test_to_dict_has_exact_schema_keys(guard, level):
    f = guard.Finding(level=level, title="t", detail="d", path="/x",
                      score_contribution=5, advisories=["GHSA-xxxx"])
    d = f.to_dict()
    assert set(d.keys()) == SCHEMA_KEYS, (
        f"Finding.to_dict keys drifted from the documented JSON schema: {set(d.keys())}"
    )
    assert d["level"] == level
    assert d["advisories"] == ["GHSA-xxxx"]


def test_advisories_default_is_independent(guard):
    """Mutable default must not be shared across instances."""
    a = guard.Finding(level="LOW", title="a")
    b = guard.Finding(level="LOW", title="b")
    a.advisories.append("GHSA-1")
    assert b.advisories == [], "advisories default list is shared across instances!"


# ─── _wrap_finding normaliser ─────────────────────────────────────────────────

def test_wrap_finding_passes_through_finding(guard):
    f = guard.Finding(level="HIGH", title="t")
    assert guard._wrap_finding(f) is f


def test_wrap_finding_converts_tuple(guard):
    f = guard._wrap_finding(("CRITICAL", "some message"))
    assert isinstance(f, guard.Finding)
    assert f.level == "CRITICAL"
    assert f.title == "some message"


def test_wrap_finding_handles_scalar(guard):
    f = guard._wrap_finding("bare string")
    assert isinstance(f, guard.Finding)
    assert f.level == "INFO"
    assert f.title == "bare string"
