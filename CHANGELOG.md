# Changelog

All notable changes to `shai_hulud_guard` are documented here.
Format adapted from [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet.

## [2.4.0] — 2026-05-20

### Added
- **`Finding` dataclass.** All internal findings now flow through a structured
  type (`level`, `title`, `detail`, `path`, `score_contribution`, `advisories`)
  instead of ad-hoc tuples. Backported from the archived v2.0 branch and
  extended with `advisories: List[str]` for GHSA/CVE cross-references.
- **`--json` output mode.** Machine-readable output for CI integration and
  LLM handoff. Suppresses banner and ANSI colour, emits a single JSON object
  with the exact schema documented in `docs/JSON_SCHEMA.md`. Schema kept
  stable across all modes that produce findings (`--scan`, `--check`,
  `--check-pypi`, `--lockcheck`, `--diagnose`).
- **`--diagnose` mode.** Writes a forensic report (`shai_hulud_report_<UTC>.txt`)
  containing system info (OS, Python, CPU, hostname, user, CI-env, shell,
  timestamp — no credentials), the full findings list, and an LLM-ready
  summary. Useful for incident handoff to an analyst.
- **CVE/GHSA advisory cross-references.** `KNOWN_BAD` entries carry an
  `advisories: List[str]` field of authoritative GitHub Advisory Database (GHSA)
  IDs, populated from OSV.dev and surfaced in `--json` findings. Kept current by
  the new maintainer tool `tools/refresh_advisories.py` (queries OSV *offline* —
  the scanner itself never phones home; see CLAUDE.md §5.4). Only the
  supply-chain / malicious-code advisory matching the `bad` version is recorded
  (unrelated CVEs in the same package are excluded).
- **`docs/THREAT_MODEL.md`** — explicit attack chain for waves 1-5,
  mapped row-by-row to defensive checks/patterns/modes.
- **`docs/DESIGN.md`** — invariants, trade-offs, non-goals.
- **`docs/JSON_SCHEMA.md`** — exact JSON output schema, with an example
  small enough to paste into a frontier LLM for further suggestions.
- **`benchmarks/run_calibration.py`** + **`BENCHMARKS.md`** — runs the
  scanner against the top-50 npm + top-50 PyPI packages live and reports
  FP rate, TP rate (on KNOWN_BAD entries), and timing distribution.
- **`legacy/`** folder preserving `shai_hulud_guard_v1.1.py` and
  `shai_hulud_guard_v2.0_interactive.py`. These versions are no longer
  maintained but document earlier design choices.
- **`LICENSE`** — GPL-3.0 (was MIT in pyproject.toml metadata only — there
  was no actual LICENSE file before).
- **`SECURITY.md`** — disclosure policy, with explicit note that the source
  contains synthetic infection artefacts (in `--self-test`) and pattern
  signatures that may trip AV/static scanners as false positives.
- **`docs/SECURITY_REVIEW.md`** — framework-driven final review against NIST
  CSF 2.0, NIST SSDF (SP 800-218), OpenSSF Scorecard, OWASP CICD-SEC Top 10,
  SLSA v1.0, MITRE ATT&CK, and CWE Top 25. Includes a scored security/
  robustness/reliability assessment and a prioritised (P0/P1/P2) roadmap.
- **104-test pytest suite** for v2.4: `test_patterns`, `test_known_bad`,
  `test_tarball`, `test_finding`, `test_typosquatting`, `test_lockfile`,
  `test_noise_filter`, `test_sentinel`, `test_json_schema`. Single canonical
  `guard` fixture (`conftest.py`), optional `legacy_*` fixtures. Includes
  regression guards for the subprocess-intent split (build-shell = MEDIUM,
  payload-shell / downloader = HIGH).
- **GitHub project infrastructure** (for the first public release):
  - `.github/workflows/ci.yml` — matrix CI (Ubuntu / macOS / Windows ×
    Python 3.8 / 3.10 / 3.12) running `ruff` + `pytest` + `--self-test`,
    with SHA-pinned actions (the tool eats its own supply-chain dog food).
  - `.github/workflows/release.yml` — on tag `v*`: per-OS PyInstaller build +
    `SHA256SUMS` + SLSA build provenance, published as a GitHub Release.
  - `.github/workflows/codeql.yml` + `scorecard.yml` — CodeQL code-scanning and
    OpenSSF Scorecard, surfaced in the repo Security tab.
  - Dependabot, issue templates (incl. an **IOC-report** form), PR template,
    `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CODEOWNERS`; live README badges.
  - SSH-signed commits + signed `v2.4.0` tag → "Verified" history.
- **`tools/refresh_advisories.py`** — maintainer-only OSV.dev advisory refresh
  helper (stdlib-only; never invoked by the scanner).

### Changed
- **License: MIT → GPL-3.0.** pyproject.toml metadata updated; full LICENSE added.
- **Single canonical version.** `shai_hulud_guard.py` is now the only
  supported entry point; v1.1 and v2.0 archived to `legacy/`.
- **README.md and CLAUDE.md** rewritten to describe v2.4 architecture only.
- **Calibration hardening** (driven by `benchmarks/run_calibration.py`, which
  surfaced false positives in legitimate top-50 packages):
  - Home-wipe pattern now matches only bare `rm -rf ~` / `~/` / `$HOME`, not
    `rm -rf ~/subdir` (legit build scripts — fixed Pillow `depends/*.sh`).
  - `ptrace` / `process_vm_readv` patterns gained word boundaries (was matching
    `depTrace` in vite/webpack bundles).
  - OIDC `id-token` pattern requires literal `id[-_]token` + bounded gap (was
    matching "Invalid token … write" across kilobytes of prettier's TS bundle).
  - Base64-literal and AWS-credential patterns require payload/exfil context.
  - `_distrib_noise_filter` restructured: **`_NOEXEC_DIRS`** (tests + CI:
    `.github`, `.evergreen`, `.circleci`, `.azure-pipelines`, …) demote
    CRITICAL→MEDIUM and suppress lower (code there doesn't run on install);
    soft-noise dirs (docs, vendored) keep the milder one-level demotion. Fixed
    false 100/55/62 scores on Pillow, virtualenv, pymongo. See `docs/DESIGN.md §2.5`.
  - PyPI path now uses the shared `_distrib_noise_filter` (removed a stale
    inline copy).
- **Benchmark pinned to stable versions** (not `latest`) for run-to-run
  reproducibility and to exclude transient publish-age noise. Pinning then
  surfaced a second tier of reproducible FPs, also fixed:
  - **Subprocess analysis split by intent** (supersedes the earlier
    CRITICAL→HIGH downgrade): a network downloader (`curl`/`wget`), or a shell
    carrying a download / pipe-to-shell / remote-`-c` / reverse-shell / encoded
    payload, stays **HIGH**; a *bare* local shell interpreter (matplotlib
    `setupext.py` runs `["sh","./autogen.sh"]`; numpy/scipy/lxml shell out to
    configure/make) is **MEDIUM**. Running a local build script is not the worm's
    behaviour; download-pipe-execute is. (matplotlib 95→25, numpy 37→21; no
    change to the true-positive set.) See `docs/DESIGN.md §2.9`.
  - Root-level CI config **files** (`azure-pipelines.yml`, `.travis.yml`,
    `.gitlab-ci.yml`, `tox.ini`, …) added to non-executing treatment via
    `_NOEXEC_FILES` (matplotlib shipped `azure-pipelines.yml` at root).
  - `_prev_version_npm` now **skips SemVer pre-release versions** as the
    comparison baseline (react-dom@18.2.0 was being diffed against an
    `0.0.0-experimental-…` snapshot → false maintainer-drift).
  - New-maintainer-added downgraded **HIGH→MEDIUM**, maintainer-removed
    MEDIUM→LOW: a new maintainer is the worm's vector but also extremely common
    in healthy projects (react-dom legitimately added a maintainer). (react-dom 30→10.)
  - Large-tarball threshold raised **800 KB → 1500 KB** (modern legit packages
    routinely exceed 1 MB; the worm payload was ~2.3 MB).

### Fixed
- `--json` early-return paths for confirmed-malicious packages now populate the
  JSON sink and set exit code 1 (was emitting only the schema skeleton).
- `shell=True` in `_setup_scheduled_scan` (Windows Task Scheduler) replaced with
  list-form `subprocess.run` to honour the §5.8 no-shell invariant.
- **OPEN-2 maintainer-scoring mismatch.** `run_check` STEP 2.5 scored a *removed*
  maintainer (LOW) at +10 via a binary `if HIGH else 10`; it now maps by exact
  level (removed/LOW = +0, added/MEDIUM = +10, HIGH = +20), matching CLAUDE.md §3.
- **`@ctrl/tinycolor` misattribution.** The Wave-1 `KNOWN_BAD` entry was
  `tinycolor2` — a different, *uncompromised* package (0 OSV vulns). Corrected to
  `@ctrl/tinycolor` (GHSA-qjqf-7j6f-82c4), matching the cited StepSecurity
  "ctrl-tinycolor" post-mortem and OSV.
- **`build.py` build target.** Referenced a non-existent `"shai_hulud_guard V2.0.py"`
  (archived to `legacy/`), so `python build.py` failed; now builds the canonical
  `shai_hulud_guard.py`. `build.ps1` + `Makefile` updated to match (dead
  `--v1`/`--v2` targets removed); build now also prints the artifact SHA-256.
- **`QUICKSTART.md`** rewritten for the v2.4 flag-based CLI (was describing the
  archived v2.0 interactive menu and nonexistent `install.sh`/`install.bat`).

### Notes
This release consolidates three parallel development tracks. The interactive
TUI from v2.0 was intentionally *not* carried forward — see `docs/DESIGN.md`
for the reasoning. The flagship CLI is fully scriptable and CI-friendly,
and the new `--json` mode makes it composable with other tooling.

## [2.3.0] — 2026-05-19

### Added
- **Proactive protection mode** (`--protect` / `--unprotect`).
  Generates platform-specific install-wrapper scripts (`npm_safe.sh|ps1`,
  `pip_safe.sh|ps1`), a SHA-pinned GitHub Actions workflow, and a
  pre-commit hook template. Optional Phase 2 installs them: shell aliases,
  `save-exact=true` in `.npmrc`, daily cron / Task Scheduler job.
  Every modification is sentinel-wrapped; `--unprotect` removes only those
  blocks without touching pre-existing user content.
- **Typosquatting detection.** Levenshtein-distance check (≤ 2) against a
  curated list of 80 popular npm packages. Wired into `--check`.
- **Self-test** (`--self-test`). Creates synthetic infection artefacts in a
  temp directory, runs the scanner, asserts 6 detection invariants.
  Sandboxed; never executes any code.
- **`--verify`** mode for post-patch re-scan.
- **`--install-hook` / `--setup-alias` / `--setup-npmrc` / `--setup-cron`**
  non-interactive flags for `--protect`.
- Heuristic amplifiers wired into `--check` STEP 2.5: maintainer drift,
  semver-gap anomaly, new-dependency diff vs previous version.
- Exit codes from `--check` and `--check-pypi`: exit 1 when `risk_score ≥ 40`.
  Enables wrapper scripts to block installs programmatically.

### Changed
- **AWS credential pattern tightened.** Previously fired on any reference
  to `AWS_SECRET_ACCESS_KEY` (false-positive on `boto3`/`botocore`'s own
  session.py). Now requires HTTP-exfiltration context.
- **`atob()` pattern tightened.** Previously fired on any `atob(` call
  (false-positive on legitimate browser-API usage in dist files). Now
  requires an embedded base64 literal of ≥ 40 chars.
- **Pure test directories** (`/tests/`, `/__tests__/`, `/spec/`, `/test_`,
  `/fixtures/`) suppress all non-CRITICAL findings — test files do not
  execute during install.

### Fixed
- Windows cp1252 encoding errors when stdout was non-UTF-8.
- `SyntaxWarning: invalid escape sequence '\.'` in the PowerShell pip
  wrapper template.

## [2.2.0] — 2026-05-19

### Added
- Maintainer-change, version-gap, and new-dependency detection
  (`check_maintainer_change`, `check_version_gap`, `check_new_dependencies`).

### Changed
- Pattern calibration tightened against a suite of legitimate packages
  (numpy, react, django, flask, lodash, cryptography). All score ≤ 25/100
  with no genuine false positives; known-bad packages
  (intercom-client@7.0.4, @tanstack/react-router@1.169.5) confirmed
  CRITICAL.

## [2.1.0] — 2026-05-19

### Added
- **PyPI support** (`--check-pypi`). Pre-install analysis for Python
  packages: PyPI JSON API metadata, sdist tarball scan, `.whl` wheel scan
  (zip), SHA-256 integrity verification, removed-version detection.
- `_check_pip_packages()` — cross-references `pip list` output against
  `KNOWN_BAD` PyPI entries during `--scan`.
- `_distrib_noise_filter()` shared between npm and PyPI tarball scanning.
- `_strip_comments()` removes `//`, `/* */`, `#` comments before pattern
  matching to reduce false positives in source files.

## [2.0.0] — 2026-05-19

### Added
- **Lockfile deep analysis** (`--lockcheck`). Detects non-registry
  `resolved` URLs, missing `integrity` hashes, lifecycle scripts embedded
  in lockfile entries, and known-bad version cross-references. Handles
  lockfile v1 (nested `dependencies`) and v2/v3 (`packages` dict with
  `node_modules/` prefix) via `_lockfile_packages()`.
- **Infection case classifier** (`classify_infection`). Returns one of
  CLEAN / UNCERTAIN / LOW_CONFIDENCE / DAEMON_ONLY / PACKAGES_ONLY /
  FULL_COMPROMISE / LOCKFILE_TAMPERED with confidence
  DEFINITIVE/HIGH/MEDIUM/LOW.
- **`--patch` mode.** Runs `--scan`, classifies the infection, generates
  per-case remediation scripts (`remove_daemon.sh|ps1`, `clean_packages.sh|ps1`),
  optionally executes safe steps with `--auto`.
- **Windows daemon detection.** Queries Task Scheduler + Startup folder for
  known persistence names (`gh-token-monitor`, `github-token-monitor`, etc.).

### Note
This is the version named `2.0.0` in pyproject.toml from a prior development
track. **Not** the same as `shai_hulud_guard V2.0.py` (the interactive
parallel branch, now archived in `legacy/`).

## [1.1.0] — 2025-12-XX

### Added
- Initial release: `--scan`, `--check`, `--incident` modes.
- `MALICIOUS_PATTERNS` table, `KNOWN_BAD` constant, tarball deep-scan,
  pre-install registry analysis.
- See `legacy/shai_hulud_guard_v1.1.py` for the preserved source.

[Unreleased]: https://github.com/USER/shai-hulud-guard/compare/v2.4.0...HEAD
[2.4.0]: https://github.com/USER/shai-hulud-guard/releases/tag/v2.4.0
[2.3.0]: https://github.com/USER/shai-hulud-guard/releases/tag/v2.3.0
[2.2.0]: https://github.com/USER/shai-hulud-guard/releases/tag/v2.2.0
[2.1.0]: https://github.com/USER/shai-hulud-guard/releases/tag/v2.1.0
[2.0.0]: https://github.com/USER/shai-hulud-guard/releases/tag/v2.0.0
[1.1.0]: https://github.com/USER/shai-hulud-guard/releases/tag/v1.1.0
