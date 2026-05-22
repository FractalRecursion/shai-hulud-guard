# legacy/

This folder preserves earlier versions of `shai_hulud_guard` for reference.
**These files are not maintained.** The supported canonical version is the
`shai_hulud_guard.py` in the project root.

## Files

### `shai_hulud_guard_v1.1.py`  (975 lines)

The original flag-based scanner. Three modes: `--scan`, `--check`, `--incident`.
Minimal CLI, no external dependencies, smallest surface area to audit. Kept here
because the small size makes it useful as a self-contained CI scanner where the
v2.3 feature set is overkill.

Differences vs canonical v2.3:
- No PyPI support
- No lockfile deep audit
- No typosquatting detection
- No infection classifier / patch generation
- No proactive protection setup
- No self-test
- No structured Finding output

### `shai_hulud_guard_v2.0_interactive.py`  (1,496 lines)

An alternative parallel branch that prioritised an interactive menu UI and
an LLM-ready diagnosis report. Contains a `Finding` dataclass, an auto-fix
flow with per-finding confirmation, and a `generate_diagnosis_report()`
function that emits a structured forensic dump suitable for handing to an
LLM analyst.

The interactive UI itself is not present in v2.3 (intentionally — see
`docs/DESIGN.md`). The `Finding` dataclass and `generate_diagnosis_report()`
concepts were ported forward into v2.3.

## Why preserve them?

1. The two files document design choices that were considered and rejected.
   Reading them helps a future maintainer understand *why* v2.3 looks the way
   it does — for example, why there is no interactive menu (UX trade-off
   discussed in `docs/DESIGN.md`).
2. v1.1 may still be useful as a tiny single-file scanner for CI contexts
   that don't need the v2.3 feature set.
3. Removing them would lose information that no future `git log` can recover,
   since these were built before the repo had a git history.

## What about pytest coverage?

The original test suite (`tests/`) targets v1.1 and v2.0 internals. As part of
the v2.4 release the suite was updated to cover v2.3 architecture. A small
subset of pattern-detection and known-bad-list tests still exercises the
shared `MALICIOUS_PATTERNS` and `KNOWN_BAD` constants which carry forward.

If you want to run v1.1 or v2.0 tests against the legacy files, the originals
are reachable in `git log --diff-filter=R --follow tests/`.
