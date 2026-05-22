# Contributing to shai_hulud_guard

Thanks for your interest. This is a **forensic security tool**: it runs on
developer laptops and CI runners, often while a machine is *suspected to be
compromised*. A subtle mistake here has an asymmetric cost — a false negative
can leave a victim believing a poisoned machine is clean, and a false positive
can push a panicked victim to wipe a machine that was fine. Please read this
before opening a PR. The authoritative, in-depth rules live in
[`CLAUDE.md`](CLAUDE.md); this file is the short version.

## Development setup

```bash
python -m pip install -e ".[dev]"     # ruff, pytest, pyinstaller
python -m pytest                      # 101 tests, ~0.3s
python -m ruff check .                # lint
python shai_hulud_guard.py --self-test  # 6/6 synthetic-infection roundtrip
```

The tool is a **single file** (`shai_hulud_guard.py`) with **zero runtime
dependencies** and must run on a clean Python 3.8+. Do not split it into a
package and do not add a runtime import — the "curl one file and run it"
deploy story is part of its incident-response value.

## The non-negotiable invariants (`CLAUDE.md §5`)

Every PR must preserve all of these:

1. **Never execute target package code.** Tarballs/wheels are read in memory
   (`extractfile` / `zf.read`), never extracted to disk, never `exec`/`eval`/`node`/`bun`.
2. **Never auto-revoke or rotate credentials.** The worm's daemon wipes `~/` on
   token revocation; rotation is a *printed manual checklist*, ordered after
   daemon removal.
3. **Never read credential file contents** — presence/path only.
4. **Never phone home.** Outbound HTTPS only to the npm and PyPI registries.
   No telemetry, no `requests` dependency.

If a feature seems to need any of the above, redesign the feature.

## Adding an IOC or detection pattern

This is the most sensitive change you can make. A regex shipped here can mark
someone's machine as infected.

1. **Cite an authoritative public source** in a comment above the entry, in the
   order of authority in `CLAUDE.md §4.7`: GHSA → NVD → OSV → Datadog →
   CISA → Wiz → StepSecurity. **No unsourced reports** (Twitter/X, screenshots).
2. **Add an exemplar** to `tests/test_patterns.py::EXEMPLARS` (a pattern with no
   exemplar fails the suite by design).
3. **Calibrate.** Run `python benchmarks/run_calibration.py` — the false-positive
   set (top npm/PyPI packages) must stay within thresholds, and the
   true-positive set must stay `CRITICAL`. Use non-greedy regexes.

## Commits

- Commits are **signed** (this repo uses SSH commit signing; see the README
  badge). Please sign your commits so they show as **Verified**.
- Keep the PR checklist green: `ruff`, `pytest`, `--self-test`.

## Reporting vulnerabilities

Do **not** open a public issue for a vulnerability *in this tool*. Use private
vulnerability reporting — see [`SECURITY.md`](SECURITY.md).
