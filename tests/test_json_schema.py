"""
Tests for the --json output schema (docs/JSON_SCHEMA.md).

We exercise the JSON machinery directly (no network) by enabling JSON mode,
recording a mode result, and inspecting the captured _JSON_RESULT. This keeps
the test fast and offline while still validating the documented schema.
"""
from __future__ import annotations

import json

import pytest

TOP_LEVEL_KEYS = {
    "schema_version", "tool", "mode", "target", "risk_score",
    "case", "confidence", "exit_code", "findings", "llm_instructions",
}
FINDING_KEYS = {"level", "title", "detail", "path", "score_contribution", "advisories"}


@pytest.fixture
def json_capture(guard):
    """Enable JSON mode without hijacking stdout, yield, then restore."""
    guard._JSON_MODE = True
    guard._JSON_RESULT.clear()
    try:
        yield guard
    finally:
        guard._JSON_MODE = False
        guard._JSON_RESULT.clear()


def test_record_populates_core_fields(json_capture):
    g = json_capture
    g._json_record_mode_result(
        mode="check",
        target="lodash@4.17.21",
        risk_score=0,
        case=g.CASE_CLEAN,
        confidence="DEFINITIVE",
        findings=[],
    )
    r = g._JSON_RESULT
    assert r["mode"] == "check"
    assert r["target"] == "lodash@4.17.21"
    assert r["risk_score"] == 0
    assert r["case"] == "CLEAN"
    assert r["exit_code"] == 0
    assert r["findings"] == []


def test_high_risk_sets_exit_code_1(json_capture):
    g = json_capture
    g._json_record_mode_result(
        mode="check", target="x@1", risk_score=80,
        case=g.CASE_PACKAGES_ONLY, confidence="DEFINITIVE",
        findings=[g.Finding(level="CRITICAL", title="bad", score_contribution=80)],
    )
    assert g._JSON_RESULT["exit_code"] == 1


def test_finding_dicts_match_schema(json_capture):
    g = json_capture
    g._json_record_mode_result(
        mode="check", target="x@1", risk_score=50,
        case=g.CASE_UNCERTAIN, confidence="MEDIUM",
        findings=[g.Finding(level="HIGH", title="t", detail="d", path="/p",
                            score_contribution=20, advisories=["GHSA-zzzz"])],
    )
    findings = g._JSON_RESULT["findings"]
    assert len(findings) == 1
    assert set(findings[0].keys()) == FINDING_KEYS
    assert findings[0]["advisories"] == ["GHSA-zzzz"]


def test_advisory_lookup_enriches_finding(json_capture):
    """advisory_lookup attaches IDs to findings whose title contains the key."""
    g = json_capture
    g._json_record_mode_result(
        mode="check", target="intercom-client@7.0.4", risk_score=100,
        case=g.CASE_PACKAGES_ONLY, confidence="DEFINITIVE",
        findings=[g.Finding(level="CRITICAL", title="CONFIRMED MALICIOUS: intercom-client")],
        advisory_lookup={"intercom-client": ["GHSA-test-1234"]},
    )
    assert g._JSON_RESULT["findings"][0]["advisories"] == ["GHSA-test-1234"]


def test_legacy_tuple_findings_are_normalised(json_capture):
    """A legacy (level, msg) tuple must serialise into the Finding schema."""
    g = json_capture
    g._json_record_mode_result(
        mode="scan", target="/proj", risk_score=10,
        case=g.CASE_UNCERTAIN, confidence="LOW",
        findings=[("MEDIUM", "a tuple finding")],
    )
    f = g._JSON_RESULT["findings"][0]
    assert set(f.keys()) == FINDING_KEYS
    assert f["level"] == "MEDIUM"
    assert f["title"] == "a tuple finding"


def test_full_object_is_json_serialisable(json_capture):
    """The captured result + defaults must round-trip through json.dumps/loads."""
    g = json_capture
    g._json_record_mode_result(
        mode="check", target="x@1", risk_score=0,
        case=g.CASE_CLEAN, confidence="DEFINITIVE", findings=[],
    )
    # Mimic _json_mode_exit_and_emit's defaults
    r = dict(g._JSON_RESULT)
    r.setdefault("schema_version", "1.0")
    r.setdefault("tool", {"name": "shai_hulud_guard", "version": g.VERSION})
    r.setdefault("llm_instructions", g._LLM_PROMPT)
    s = json.dumps(r, ensure_ascii=False)
    back = json.loads(s)
    assert TOP_LEVEL_KEYS.issubset(set(back.keys()))
