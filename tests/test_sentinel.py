"""
Tests for _sentinel_wrap / _sentinel_strip — the reversibility primitives that
make --unprotect able to remove exactly what --protect added (CLAUDE.md §5.10).
"""
from __future__ import annotations


def test_wrap_adds_both_markers(guard):
    wrapped = guard._sentinel_wrap("alias npm='x'")
    assert guard._SHAI_START in wrapped
    assert guard._SHAI_END in wrapped
    assert "alias npm='x'" in wrapped


def test_strip_removes_wrapped_block(guard):
    original = "export PATH=/usr/bin\n"
    wrapped = original + guard._sentinel_wrap("alias npm='x'")
    stripped = guard._sentinel_strip(wrapped)
    assert "alias npm='x'" not in stripped
    assert guard._SHAI_START not in stripped
    assert guard._SHAI_END not in stripped
    assert "export PATH=/usr/bin" in stripped, "pre-existing user content was destroyed"


def test_roundtrip_returns_to_original(guard):
    original = "line1\nline2\n"
    wrapped = original + guard._sentinel_wrap("injected")
    assert guard._sentinel_strip(wrapped).strip() == original.strip()


def test_strip_is_idempotent(guard):
    original = "content\n"
    once = guard._sentinel_strip(original + guard._sentinel_wrap("x"))
    twice = guard._sentinel_strip(once)
    assert once == twice


def test_strip_handles_multiple_blocks(guard):
    text = (
        "user line\n"
        + guard._sentinel_wrap("block A")
        + "middle user line\n"
        + guard._sentinel_wrap("block B")
    )
    stripped = guard._sentinel_strip(text)
    assert "block A" not in stripped
    assert "block B" not in stripped
    assert "user line" in stripped
    assert "middle user line" in stripped


def test_strip_noop_when_no_sentinel(guard):
    plain = "just a normal config\nwith two lines\n"
    assert guard._sentinel_strip(plain) == plain
