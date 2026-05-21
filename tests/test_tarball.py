"""
Tests for scan_tarball_bytes — the core safety-critical inspector (v2.4).

What we are guarding here:
  - Worm payload filenames are detected by basename.
  - IOC patterns inside JS source members are detected.
  - Legitimate i18n high-codepoint unicode tables are NOT flagged
    (the CLAUDE.md §5.6 invariant).
  - A binary garbage member with .js suffix does NOT crash the scanner.
  - A non-gzip blob does NOT raise (the function must degrade gracefully —
    real users may hand it a partially-downloaded or wrong-format tarball).
"""
from __future__ import annotations


def _result_set(hits):
    """scan_tarball_bytes returns (filepath, desc, risk, snippet) tuples.
    Reduce to (filepath, desc, risk) for assertions."""
    return {(fp, desc, risk) for fp, desc, risk, _snip in hits}


# ─── Worm payload filename detection ─────────────────────────────────────────

def test_payload_filename_detected(guard, payload_filename_tarball):
    hits = guard.scan_tarball_bytes(payload_filename_tarball)
    rs = _result_set(hits)
    assert any(
        "router_init.js" in fp and "payload filename" in desc.lower() and risk == "CRITICAL"
        for fp, desc, risk in rs
    ), f"Expected payload-filename CRITICAL finding; got: {rs}"


# ─── Worm identity string inside JS member ───────────────────────────────────

def test_worm_string_detected(guard, worm_string_tarball):
    hits = guard.scan_tarball_bytes(worm_string_tarball)
    descs = [desc for _, desc, _, _ in hits]
    assert any("Worm identity" in d for d in descs), descs


# ─── ASCII-range unicode obfuscation IS detected ─────────────────────────────

def test_ascii_obfuscation_detected(guard, ascii_obfuscated_tarball):
    hits = guard.scan_tarball_bytes(ascii_obfuscated_tarball)
    descs = [desc for _, desc, _, _ in hits]
    assert any("\\u escapes" in d for d in descs), descs


# ─── High-codepoint i18n tables are NOT flagged (CLAUDE.md §5.6) ─────────────

def test_i18n_high_codepoints_not_flagged(guard, lodash_like_unicode_tarball):
    hits = guard.scan_tarball_bytes(lodash_like_unicode_tarball)
    descs = [desc for _, desc, _, _ in hits]
    assert not any("\\u escapes" in d for d in descs), (
        f"Lodash-like i18n table triggered the unicode-escape regex — "
        f"this regresses CLAUDE.md §5.6. Hits: {descs}"
    )


# ─── Robustness ──────────────────────────────────────────────────────────────

def test_clean_tarball_has_no_findings(guard, clean_tarball):
    assert guard.scan_tarball_bytes(clean_tarball) == []


def test_binary_garbage_does_not_crash(guard, binary_garbage_tarball):
    """A binary member with .js suffix must be tolerated, not crash."""
    hits = guard.scan_tarball_bytes(binary_garbage_tarball)
    assert isinstance(hits, list)


def test_non_gzip_input_does_not_crash(guard):
    """Real users pipe in whatever the registry returned. Bad gzip headers
    must degrade gracefully (the scanner logs a warning and returns [])."""
    hits = guard.scan_tarball_bytes(b"not a tarball")
    assert hits == []


def test_empty_input_does_not_crash(guard):
    hits = guard.scan_tarball_bytes(b"")
    assert hits == []
