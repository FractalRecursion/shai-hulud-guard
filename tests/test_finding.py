"""
Tests for the v2.0 Finding dataclass.

The Finding class is the only structured output type in v2.0. The colour
and icon maps must cover every level the rest of the code can emit, or a
finding silently renders without an icon and the user misses it.
"""
from __future__ import annotations

import pytest

ALL_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def test_finding_dataclass_basic(v2):
    f = v2.Finding(check="Test", level="HIGH", title="t", detail="d")
    assert f.check == "Test"
    assert f.level == "HIGH"
    assert f.title == "t"
    assert f.detail == "d"
    assert f.path == ""
    assert f.fixable is False
    assert f.fix_label == ""
    assert f.fix_fn is None


@pytest.mark.parametrize("level", ALL_LEVELS)
def test_icon_covers_every_level(v2, level):
    f = v2.Finding(check="x", level=level, title="t", detail="d")
    icon = f._icon()
    assert icon and icon != "·", (
        f"Level {level!r} falls through to default icon — _icon() map "
        "needs an explicit entry."
    )


@pytest.mark.parametrize("level", ALL_LEVELS)
def test_color_covers_every_level(v2, level):
    f = v2.Finding(check="x", level=level, title="t", detail="d")
    col = f._col()
    assert col and col != "0", (
        f"Level {level!r} falls through to default colour — _col() map "
        "needs an explicit entry."
    )


def test_display_runs_without_exception(v2, capsys):
    """display() prints. We don't snapshot the formatting, but it must not raise
    on any combination of optional fields."""
    cases = [
        v2.Finding(check="A", level="CRITICAL", title="t", detail="line1\nline2"),
        v2.Finding(check="A", level="HIGH",     title="t", detail="d", path="/x/y"),
        v2.Finding(check="A", level="MEDIUM",   title="t", detail="d",
                   fixable=True, fix_label="do thing", fix_fn=lambda: (True, "ok")),
        v2.Finding(check="A", level="LOW",      title="t", detail=""),
        v2.Finding(check="A", level="INFO",     title="t", detail="d", path=""),
    ]
    for f in cases:
        f.display()
    out = capsys.readouterr().out
    # Sanity: each finding contributed something to stdout.
    for f in cases:
        assert f.title in out


def test_fixable_finding_carries_fix_fn(v2):
    """A fixable Finding must store its closure and execute it on demand."""
    calls = []

    def fix():
        calls.append("fix")
        return True, "fixed it"

    f = v2.Finding(check="X", level="CRITICAL", title="t", detail="d",
                   fixable=True, fix_label="fix-it", fix_fn=fix)
    assert f.fixable is True
    assert f.fix_fn is not None
    ok, msg = f.fix_fn()
    assert ok is True
    assert msg == "fixed it"
    assert calls == ["fix"]
