# CLAUDE.md — Shai-Hulud Guard

This file is the instruction surface for Claude Code when working on this repository. It is the **single source of truth** about how the codebase is laid out, which invariants must never be regressed, where IOC data comes from, and what is still missing from the project infrastructure.

> **Read this file fully before editing any `.py` file.** This is a security tool. A subtle mistake — adding a `requests` import, broadening a regex, executing tarball code, auto-revoking a token — can either render the scanner blind, produce false negatives that mislead a victim during active incident response, or cause irreversible data loss on a developer machine.

---

## 1. Repository shape

Single-folder Python project, **runtime stdlib only**, Python 3.8+, runs on **Linux / macOS / Windows**. Dev dependencies (`pytest`, `ruff`, `pyinstaller`) are pinned in `pyproject.toml`'s `[project.optional-dependencies] dev` group only — the runtime tool ships with zero third-party imports.

```
Shai_Hulud_Guard/
├── CLAUDE.md                  ← this file (instructions to Claude Code)
├── README.md                  ← user-facing docs
├── QUICKSTART.md              ← user-facing quick-start (v2.4 flag-based CLI)
├── CHANGELOG.md               ← version history
├── LICENSE                    ← GPL-3.0
├── SECURITY.md                ← disclosure policy + project-is-defensive note
├── shai_hulud_guard.py        ← v2.4.0  canonical CLI (~3,200 lines)
│
├── pyproject.toml             ← project metadata + ruff config + pytest config
├── Makefile                   ← Linux/macOS conveniences (install/test/lint/build)
├── build.ps1                  ← Windows PowerShell wrapper around build.py
├── build.py                   ← Cross-platform PyInstaller build
│
├── tests/                     ← pytest suite (originally for v1.1+v2.0;
│   │                            being updated for v2.4 in Phase 4)
│   ├── conftest.py
│   ├── test_patterns.py
│   ├── test_known_bad.py
│   ├── test_tarball.py
│   └── test_finding.py
│
├── docs/
│   ├── RUFF.md                ← what ruff does + how this project uses it
│   ├── THREAT_MODEL.md        ← (Phase 5B) attack chain → defensive features
│   ├── DESIGN.md              ← (Phase 5B) invariants, trade-offs, non-goals
│   └── JSON_SCHEMA.md         ← (Phase 5A) --json output schema, with LLM-ready example
│
├── benchmarks/                ← (Phase 5C) live-registry FP/TP measurement
│   ├── run_calibration.py
│   └── BENCHMARKS.md
│
├── tools/                     ← maintainer-only dev tooling (NEVER run by the scanner)
│   └── refresh_advisories.py  ← refresh KNOWN_BAD advisories from OSV.dev
│
├── legacy/                    ← archived, NOT maintained
│   ├── README.md              ← what's here and why
│   ├── shai_hulud_guard_v1.1.py
│   └── shai_hulud_guard_v2.0_interactive.py
│
├── .gitignore                 ← excludes runtime-generated reports + venv + dist/
└── .gitattributes             ← LF line endings for source, CRLF for .bat/.ps1
```

**One canonical script.** `shai_hulud_guard.py` is the only supported entry point.

The previous "v1.1 small CLI + v2.0 interactive UI" dual architecture is **archived** in `legacy/`. Earlier CLAUDE.md instructions to keep both versions in sync are **superseded** — v2.4 supersedes both. The legacy files are preserved for reference and as a tiny single-file fallback in CI contexts that don't need the v2.4 feature set, but they receive no maintenance.

---

## 2. v2.4 modes (the CLI surface)

Argparse contract — do not break without bumping the major version:

```
python shai_hulud_guard.py --scan [--path DIR] [--json]
python shai_hulud_guard.py --check <pkg>[@<version>] [--json]
python shai_hulud_guard.py --check-pypi <pkg>[==<version>|@<version>] [--json]
python shai_hulud_guard.py --lockcheck [--path DIR] [--json]
python shai_hulud_guard.py --patch [--path DIR] [--auto]
python shai_hulud_guard.py --verify [--path DIR]
python shai_hulud_guard.py --self-test
python shai_hulud_guard.py --diagnose [--path DIR] [--json]
python shai_hulud_guard.py --protect [--path DIR]
                          [--install-hook] [--setup-alias] [--setup-npmrc] [--setup-cron]
python shai_hulud_guard.py --unprotect [--path DIR]
python shai_hulud_guard.py --incident
python shai_hulud_guard.py --version
```

### Module structure  (top to bottom in the file)

| Section | What it contains |
|---|---|
| Imports + Windows UTF-8 stdout reconfigure | First ~90 lines. Stdlib only. |
| `VERSION` and other constants | `KNOWN_BAD`, `HIGH_VALUE_TARGETS`, `DAEMON_PATHS`, `CREDENTIAL_FILES`, `MALICIOUS_FILENAMES`, `MALICIOUS_PATTERNS`. |
| Typosquatting | `_TOP_NPM_PACKAGES`, `_levenshtein()`, `check_typosquatting()`. |
| Output helpers | `ok` / `info` / `warn` / `crit` / `dim` / `head` / `subh`. ANSI colored. |
| Pattern engine | `scan_text()`, `scan_tarball_bytes()`, `scan_wheel_bytes()`, `_strip_comments()`, `_distrib_noise_filter()`. |
| Network | `fetch_json()`, `fetch_bytes()`. |
| PyPI mode | `run_pypi_check()`, `fetch_pypi_meta()`, `_check_pip_packages()`. |
| Lockfile audit | `run_lockcheck()`, `_lockfile_packages()`, `scan_lockfile()`. |
| Version heuristics | `_prev_version_npm()`, `_parse_semver()`, `check_maintainer_change()`, `check_version_gap()`, `check_new_dependencies()`. |
| npm pre-install | `run_check()`. Wired heuristics into STEP 2.5. Exits 1 if `risk_score ≥ 40`. |
| Existing-project scan | `run_scan()`, `check_windows_persistence()`. |
| Classification + patch | `classify_infection()`, `generate_remediation()`, `run_patch()`, `_write_daemon_script()`, `_write_cleanup_script()`. |
| Verify + self-test | `run_verify()`, `run_self_test()`. |
| Incident response | `run_incident()`. |
| Proactive protection | Sentinel constants, `_write_npm_wrapper()`, `_write_pip_wrapper()`, `_write_ci_workflow()`, `_write_githook_template()`, `_install_git_hook()`, `_setup_shell_alias()`, `_setup_project_npmrc()`, `_setup_scheduled_scan()`, `run_protect()`, `run_unprotect()`. |
| `main()` | Argparse + dispatch. |

### Exit codes

- `0` — clean / no critical findings / nothing to do.
- `1` — at least one risk ≥ 40 finding from `--check` / `--check-pypi`. Used by the generated `npm_safe` / `pip_safe` wrapper scripts to block installs.

A future v2.5 may introduce richer exit codes (`2` for verify failure, `3` for self-test failure, etc.). Not in scope for v2.4 — keep the contract simple.

---

## 3. Shared code architecture

### Pattern engine — `scan_text(text)`

Runs every `(regex, description, risk)` tuple from `MALICIOUS_PATTERNS` against arbitrary text using `re.search(..., re.IGNORECASE)`. Dedups results by `(description, risk)`. Returns `List[(desc, risk, snippet[:100])]`.

`_strip_comments(text, ext)` is called first to remove `//`, `/* */`, and `#` comments before pattern matching. This is **necessary** for source-file scans (`scan_tarball_bytes` / `scan_wheel_bytes`) because legitimate documentation comments contain attack-pattern *descriptions* (e.g. crypto library docs explaining `/etc/shadow`, security guides containing example shell commands). Without comment stripping, false positives on `cryptography`, `numpy`, etc. exceed 80/100.

Called from:
- `run_scan` — against each lifecycle script value in installed `node_modules/*/package.json`.
- `run_check` — against each declared lifecycle script in registry metadata, and against tarball contents.
- `run_pypi_check` — against sdist tarball + wheel zip contents.
- `run_lockcheck` — against lockfile entry strings.

### Tarball / wheel scanners

- `scan_tarball_bytes(data: bytes)` — reads gzipped tarball **in memory** via `tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")`. Walks `getmembers()`, checks each file's basename against `MALICIOUS_FILENAMES`, and for text-extension members calls `extractfile(m).read().decode("utf-8", errors="replace")` and pipes the content into `scan_text`.
- `scan_wheel_bytes(data: bytes)` — same idea but for `.whl` files via `zipfile.ZipFile(io.BytesIO(data))`.

**Nothing is ever extracted to disk. Nothing is ever executed.** Preserve this if you refactor — see invariants §5.1.

### Distribution noise filter — `_distrib_noise_filter(filepath, risk)`

Demotes findings by path class so a real malicious payload in *executing* source code outranks legitimate-but-suspicious patterns in test/CI infrastructure. Rules (precedence order):

1. Install-time files (`setup.py`, `package.json`, `preinstall.js`, `postinstall.js`, `install.js`) retain their original risk — these are the actual install-time attack surface, never demoted.
2. **Non-executing dirs** (`_NOEXEC_DIRS` — tests AND CI: `/test/`, `/tests/`, `/__tests__/`, `/spec/`, `/test_`, `/fixtures/`, `/mocks/`, `/stubs/`, `/.github/`, `/.circleci/`, `/.travis`, `/appveyor`, `/ci/`, `/.evergreen/`, `/.azure-pipelines/`, `/.buildkite/`, `/.gitlab/`, `/.teamcity/`, `/.azure/`) **and non-executing files** (`_NOEXEC_FILES` — root-level CI configs by basename: `azure-pipelines.yml`, `.travis.yml`, `.gitlab-ci.yml`, `appveyor.yml`, `tox.ini`, `noxfile.py`, `conftest.py`): code here does NOT run during `npm install` / `pip install`. Demote **`CRITICAL → MEDIUM`** (visible at +4, can't hard-block a legit package), suppress everything below CRITICAL to `LOW`.
3. `CRITICAL` outside non-executing dirs always passes through.
4. **Soft-noise dirs** (`_NOISE_DIRS` — `/doc/`, `/docs/`, `/_static/`, `/examples/`, `/demo/`, `/tools/`, `/vendor/`, `/vendored/`, `/third_party/`, `/thirdparty/`, `/external/`): demote one level (`HIGH → MEDIUM`, `MEDIUM → LOW`); `CRITICAL` stays (vendored / `tools/` code can be imported). Caller drops `LOW`. (`/tools/` = release/dev scripts shipped in sdists but not run on install — e.g. matplotlib `tools/gh_api.py`.)

Rationale + the calibration cases that drove the CRITICAL→MEDIUM demotion (Pillow, pymongo, virtualenv) are in `docs/DESIGN.md §2.5`. Regression-guarded by `tests/test_noise_filter.py`. The PyPI path uses this same shared filter (no separate inline copy).

### Network — `fetch_json()` / `fetch_bytes()`

Wrap `urllib.request.urlopen` with a `User-Agent` header (`shai-hulud-guard/<VERSION>`). 12s timeout for JSON, 45s for tarball bytes. **Adding a `requests` import breaks the "zero external dependencies" promise** that is stated in the script docstring, the README, and `pyproject.toml`. It is also a documented hardening choice — `requests` (and its transitive deps `urllib3`, `certifi`, `charset-normalizer`, `idna`) would expand the supply-chain attack surface of a security tool by ~5 packages.

### Risk scoring

Score weights are inline, not centralised. The thresholds drive the verdict copy and the exit code — touch deliberately and update the tiers in lockstep.

| Indicator | Score delta |
|---|---|
| Published `<6h` ago | +40 |
| Published `<24h` ago | +25 |
| Published `<7d` ago | +10 |
| `KNOWN_BAD` package, version not in `bad` list | +15 |
| Typosquat (distance 1) | +15 |
| Typosquat (distance 2) | +5 |
| Maintainer added vs previous *stable* version | +10 (MEDIUM) |
| Maintainer removed vs previous *stable* version | +0 (LOW, informational) |
| Anomalous version jump (>30 minor or >500 patch) | +20 |
| Large version jump (>10 minor or >100 patch) | +8 |
| New non-registry dependency | +15 each |
| New registry dependency vs previous version | +2 each |
| Lifecycle script matches `CRITICAL` pattern | +45 |
| Lifecycle script matches `HIGH` pattern | +20 |
| Lifecycle script matches `MEDIUM` pattern | +5 |
| `preinstall` hook present (any content) | +5 |
| Git/file/http(s) transitive dep | +12 each, capped at +30 |
| Tarball >1500 KB | +10 |
| Tarball pattern match `CRITICAL` | +50 |
| Tarball pattern match `HIGH` | +20 |
| Tarball pattern match `MEDIUM` | +4 |
| **SHA-512 (or SHA-1) integrity mismatch** | **+100** (immediate verdict) |

Verdict tiers:
- `0` → Proceed with caution
- `1–14` → Low — manual review recommended
- `15–39` → Moderate — verify independently
- `40–69` → High — investigate before installing  *(triggers exit code 1)*
- `≥70` → **CRITICAL — do not install**

---

## 4. Signature database — where IOC updates land

These constants are the **only place** new IOCs should be added.

### 4.1 `MALICIOUS_FILENAMES`

Exact basenames of files dropped by the worm. Flagged regardless of content. Keep this set small and high-confidence — every entry is a hard block.

```python
{ "router_init.js", "setup_bun.js", "bun_environment.js", "setup.mjs" }
```

### 4.2 `MALICIOUS_PATTERNS`

List of `(regex, description, risk_level)` tuples. `risk_level` **must** be one of the literal strings `"CRITICAL" | "HIGH" | "MEDIUM" | "LOW"` — the entire risk-scoring and colour-mapping pipeline `==`-compares against these exact strings. A typo silently demotes a finding.

Rules when adding patterns:
- Use non-greedy matches where possible.
- **Calibrate against the false-positive suite before merging.** v2.4's reference set: numpy, react, django, flask, lodash, cryptography. All must remain ≤ 25/100 with no genuine false positives. See `benchmarks/run_calibration.py`.
- **Calibrate against the true-positive suite.** Known-bad packages (intercom-client@7.0.4, @tanstack/react-router@1.169.5) must remain CRITICAL.
- Cite a public source in the surrounding comment (see §4.7).

### 4.3 `KNOWN_BAD`

Dict `{ package_name: {"bad": [versions], "waves": [wave_tags], "advisories": [ids]} }`.

Semantics:
- `bad: ["1.169.5"]` — install of this exact version triggers `CRITICAL` and stops `run_check` at risk = 100.
- `bad: []` — high-scrutiny watchlist; targeted before but no version confirmed malicious yet. `run_check` adds +15 and emits `MEDIUM`.
- `advisories: ["GHSA-…"]` — authoritative advisory IDs (GHSA preferred; NVD CVE / OSV). Surfaced in `--json` output for downstream tooling and LLM analysis. **Populated from OSV.dev** and kept current by `tools/refresh_advisories.py` (maintainer-only — the scanner never queries OSV at runtime, §5.4). Record only the supply-chain / malicious-code advisory matching the `bad` version (exclude unrelated CVEs). Empty list = none cross-referenced yet.

`waves` is a free-form list of human tags (`"Wave5-May2026"`) used in report copy.

### 4.4 `HIGH_VALUE_TARGETS`

`set(KNOWN_BAD.keys()) | {extra packages repeatedly attacked}`. Used by `run_scan` to upgrade a finding to `HIGH` even when the installed version is not on the `bad` list, and by the diagnosis report to flag deps in the package listing.

### 4.5 `DAEMON_PATHS`

Per-OS absolute paths where the worm's persistence daemon installs itself.

```python
{
  "linux":   [~/.config/systemd/user/gh-token-monitor.service],
  "darwin":  [~/Library/LaunchAgents/com.user.gh-token-monitor.plist],
  "windows": [],  # not publicly documented; see check_windows_persistence()
}
```

The Windows list is **intentionally empty** of absolute paths because public post-mortems have not documented a confirmed path. Detection on Windows is done by `check_windows_persistence()` which queries Task Scheduler and the Startup folder for known names (`gh-token-monitor`, `github-token-monitor`, `npm-helper`, `bun-helper`, `node-updater`). Do not fill in absolute paths with guesses.

### 4.6 `CREDENTIAL_FILES`

Paths the worm is documented to sweep. The scanner **lists their presence only** — never reads them. See §5.3.

### 4.7 Authoritative external sources for updates

When extending any of the constants above, the canonical sources are (in this order of authority):

1. **GitHub Advisory Database (GHSA)** — `https://github.com/advisories`. Most authoritative for npm/PyPI ecosystem-specific advisories. Use this for `advisories` field in `KNOWN_BAD`. The npm registry mirrors GHSA into `npm audit`.
2. **NIST NVD (CVE)** — `https://nvd.nist.gov/`. Used when a CVE has been issued (rare for malicious-package campaigns; common for vulnerability disclosures in legitimate code).
3. **OSV (osv.dev)** — Google's unified vulnerability database. Aggregates GHSA + others into one API. Useful for cross-checking.
4. **Datadog IOC repo** — `https://github.com/DataDog/indicators-of-compromise/tree/main/shai-hulud-2.0` — most actively maintained machine-readable IOC list for this worm family. Mirror new file hashes / domains / package names from here first.
5. **CISA advisory** — `https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem`.
6. **Wiz blog** — `https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised`.
7. **Datadog Security Labs writeup** — `https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/`.
8. **StepSecurity post-mortems** — `https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised`.

**Do not add patterns from unverified user reports, Twitter/X threads alone, or screenshot-only sources.** False-positives in a forensic scanner cause real harm: they prolong incident response, encourage developers to wipe machines that were never infected, and erode trust in subsequent true-positive findings.

---

## 5. Safety invariants — **do not regress under any circumstances**

These are not style preferences. Each exists because regressing it causes irreversible damage to a victim's data, credentials, or machine. If a future refactor appears to require breaking one of these, **stop and ask the user** — there is almost always another way.

### 5.1 Never execute target package code

Tarballs and wheels are read in memory. Members are inspected via `extractfile()` / `zf.read()` and `.decode("utf-8", errors="replace")`. **At no point is the archive extracted to disk, nor any file inside it `import`-ed, `exec`-ed, `eval`-ed, or passed to `node` / `bun` / `python -c`.**

The whole point of `--check` is to inspect a package *before* installing — running it would defeat that purpose and would risk auto-detonating the very payload the user is trying to identify.

Preserve this if refactoring. Do not add a "convenient" `tarfile.extractall()` even with `members=` filtering — a malicious tarball with path-traversal members can escape even a restricted extract. In-memory `extractfile` cannot escape because nothing is written to disk.

### 5.2 Never auto-revoke tokens, never auto-rotate credentials

The worm's `gh-token-monitor` daemon polls GitHub every 60 seconds. **If it detects a token revocation, it triggers `rm -rf ~/` (Linux/macOS) or the Windows equivalent.** Revocation is therefore the most dangerous action on an infected machine, and it must happen *after* the daemon has been removed.

The scanner:
- Warns loudly when the daemon path is present (CHECK 1).
- Generates a remediation script that stops + disables + deletes the daemon file. `--auto` runs that script after asking for confirmation.
- **Defers all credential rotation to a printed manual checklist** — STEP 5 of `--incident` and STEP 5 of the patch summary.

**Never call `gh auth logout`, `npm token revoke`, `aws iam delete-access-key`, `gcloud auth revoke`, `az ad sp credential reset`, or any equivalent from the scanner.** Even if a future "convenience" feature seems valuable, do not add it without explicit, signed-off discussion in CLAUDE.md updates and the README.

### 5.3 Never read credential file contents

CHECK 5 in `run_scan` lists credential file paths only. It calls `Path.exists()` and emits a finding whose `detail` contains paths and severity guidance. **It never calls `Path.read_text()` / `read_bytes()` on these files**, never logs their contents to the report, never sends them anywhere.

`generate_diagnosis_report()` (the `--diagnose` mode) also lists credential file presence as `[EXISTS]` / `[absent]` only — basenames and paths, never values.

This rule extends to any future feature: memory snapshots, "include context for LLM", auto-upload, telemetry, etc. If a feature appears to need credential contents, redesign the feature.

### 5.4 Never make the scanner phone home

The scanner makes outbound HTTPS calls **only** to:
- `https://registry.npmjs.org/<package>` — JSON metadata fetch (`--check` mode only).
- The `dist.tarball` URL returned by the above metadata (npm CDN) — tarball fetch (`--check` mode only).
- `https://pypi.org/pypi/<package>/json` — PyPI metadata (`--check-pypi` mode only).
- The release URLs returned by the above PyPI metadata — sdist / wheel fetch (`--check-pypi` mode only).

No telemetry. No crash reporting. No analytics. No `requests.get(<anything-else>)`. The `--diagnose` report is **written to a local file** and the user pastes it themselves into an LLM — the scanner does not transmit it.

### 5.5 Pattern additions require a public source

Every new entry in `MALICIOUS_PATTERNS` or `KNOWN_BAD` must be backed by one of the sources listed in §4.7. Add the source URL in a comment on the line above the entry. This is the project's contributing rule and it exists because a regex shipped in this tool can mark someone's machine as infected — which they may then wipe.

### 5.6 The Unicode escape pattern is deliberately ASCII-scoped

`MALICIOUS_PATTERNS` contains:

```python
(r"(?:\\u00[2-7][0-9a-fA-F]){4,}",
 "ASCII chars encoded as \\u escapes (obfuscation)",  "MEDIUM"),
```

This is scoped to ` `–`` (printable ASCII) on purpose. **Do not broaden it to `\u01xx`–`\uFFxx`.** Real i18n libraries (`lodash`, `core-js`, `linebreak`, Intl polyfills) legitimately encode Unicode character tables with high-codepoint `\uXXXX` sequences. Broadening this regex floods scans of any sufficiently large `node_modules` with false-positives, and the user starts ignoring real findings.

If you ever do touch this regex, regression-test against a real lodash 4.x bundle and at least one i18n polyfill before merging.

### 5.7 The 8-step incident guide ordering is load-bearing

The order of the steps in `run_incident()` (STOP → ISOLATE → IMAGE → REMOVE DAEMON → ROTATE CREDS → AUDIT PUBLISH → REBUILD → REPORT) reflects real operational constraints. In particular:

- **STOP comes before everything** because revoking tokens before the daemon is removed triggers home-directory wipe (see §5.2).
- **ISOLATE comes before IMAGE** because the worm continues to exfiltrate while the disk is being imaged otherwise.
- **IMAGE comes before REMOVE DAEMON** because forensic evidence is destroyed once the daemon and its filesystem artifacts are deleted.

Do not "tidy up" this ordering for readability. Do not collapse steps. Do not add an early "revoke tokens" step.

### 5.8 Cross-machine portability

This tool runs on Linux, macOS, and Windows, on developer laptops and CI runners, on bare metal and in containers. Specific portability rules:

- **No hardcoded shell.** Use `subprocess.run([list, of, args])` — never `subprocess.run("cmd ...", shell=True)`. `shell=True` changes the quoting model per OS and is a command-injection surface for any value that flows in from the registry or filesystem.
- **No POSIX-only path operations.** Use `pathlib.Path` and `Path.home()`, not `os.path.expanduser` strings glued by hand, and never assume `/`.
- **Per-OS branches use `platform.system().lower()`** — values are `"linux" | "darwin" | "windows"`. Stay consistent with the existing branches in `DAEMON_PATHS` and `run_scan`'s daemon check.
- **ANSI colour on Windows** is enabled via the `sys.stdout.reconfigure(encoding="utf-8", errors="replace")` call near the top of the file. If you add new colour output, route it through `_c()` — never embed escape sequences directly.
- **`subprocess` calls have explicit `timeout=`.** A hanging `npm config get` should not freeze a scanner that a user is running because they suspect active infection.
- **Encoding is `utf-8` with `errors="replace"`** for every file read. A binary file in `node_modules` (rare but possible) must not crash the scan.

### 5.9 Impact awareness

This tool is run in two very different states, and the cost of being wrong in each is asymmetric:

| State | Cost of false negative | Cost of false positive |
|---|---|---|
| **Pre-install (`--check`)** | Developer installs malicious package → full machine + org compromise | Developer doesn't install a clean package → minor inconvenience |
| **Post-suspected-infection (`--scan`)** | Victim believes machine is clean → continues using compromised tokens, exfiltration continues | Victim wipes a clean machine → significant lost work, lost local-only data, eroded trust in scanner |

Be conservative on `--check` (prefer false-positives there: a missed install of a poisoned package is catastrophic). Be precise on `--scan` (prefer false-negatives there to false-positives: incorrectly telling someone they're infected has real cost — see CISA reports on incident-response fatigue).

### 5.10 Sentinel-based reversibility (new in v2.3+)

Every modification `--protect` makes to a pre-existing file (shell profile, `.npmrc`, crontab) is wrapped between sentinel comments:

```
# === shai-hulud-guard (remove with: python shai_hulud_guard.py --unprotect) ===
... lines ...
# === /shai-hulud-guard ===
```

`--unprotect` strips **exactly and only** the bracketed blocks. Pre-existing user content outside the sentinels is untouched.

**Do not change the sentinel strings (`_SHAI_START`, `_SHAI_END`).** Existing installs in the wild have these exact strings written into their dotfiles. Renaming them would orphan those blocks — `--unprotect` would no longer be able to remove them, leaving stale aliases pointing at deleted paths.

**Do not add `--protect` modifications outside the sentinel pattern.** Every Phase 2 modification must be wrapped, or it cannot be reversed.

### 5.11 `--diagnose` and `--json` output contain no credentials

The diagnosis report and the `--json` output emit:
- Findings (level, title, detail, path, score contribution, advisories).
- System info: OS, Python version, CPU arch, hostname, username, CI environment, shell name, scan timestamp.
- Package names and versions.
- Credential file presence (filename or `[absent]`).

They **must never** emit:
- Credential file contents.
- Environment variable values (only names, if at all).
- Network secrets / tokens / API keys.
- File contents from `node_modules` (those go through the pattern scanner; only the *match snippet* — first 100 chars of the matching region — is included).

If a future feature appears to need any of the forbidden values, redesign the feature.

---

## 6. Running the tool

### Smoke tests (quick)

```bash
python shai_hulud_guard.py --version                  # prints "shai_hulud_guard 2.4.0"
python shai_hulud_guard.py --self-test                # 6/6 assertions, ~2 seconds
python shai_hulud_guard.py --scan --path .            # scans cwd, exits 0 here
```

### Calibration baseline — must pass before any pattern change

```bash
python shai_hulud_guard.py --check lodash             # expect 0/100
python shai_hulud_guard.py --check react              # expect 0/100
python shai_hulud_guard.py --check-pypi numpy         # expect ≤ 25/100
python shai_hulud_guard.py --check-pypi django        # expect 0/100
python shai_hulud_guard.py --check intercom-client@7.0.4    # expect CONFIRMED MALICIOUS
python shai_hulud_guard.py --check @tanstack/react-router   # expect ≤ 20/100, known target warning
```

The full benchmark (`benchmarks/run_calibration.py`) hits the live registry against top-50 npm + top-50 PyPI packages and is the authoritative pre-merge check for any pattern change.

### Roundtrip protection (only on a disposable sandbox path)

```bash
python shai_hulud_guard.py --protect --setup-alias --setup-npmrc --setup-cron --path /tmp/sandbox
python shai_hulud_guard.py --unprotect --path /tmp/sandbox
```

**Never run `--protect` on system roots or other repos during dev.** It will write into your shell profile, `.npmrc`, and crontab / Task Scheduler. Use a disposable directory.

---

## 7. Style / project conventions

- **Stdlib only.** No `requests`, no `colorama`, no `click`, no `rich`. The script must run on a freshly-installed Python 3.8 with nothing else.
- **Single-file script.** Do not split into a package without explicit user instruction — the deploy story (curl one file, run it) is part of the threat-response value proposition.
- **No external network calls outside the npm and PyPI registries** (see §5.4).
- **Comment with sources.** A regex without a citation is a future false-positive waiting to happen.
- **Match existing severity vocabulary**: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`. These are strings, not enums — do not "improve" them to an enum without rewriting the comparison sites.
- **One canonical file.** Do not reintroduce the v1.1/v2.0 dual-track architecture. Legacy is in `legacy/` and stays there.

---

## 8. Project infrastructure — status

### 8.1 Test suite — `tests/` ✅ UPDATED FOR v2.4 (104 tests passing)

The pytest suite covers the canonical v2.4 module via the `guard` fixture
(`tests/conftest.py` loads root `shai_hulud_guard.py` via importlib; optional
`legacy_v1`/`legacy_v2` fixtures load `legacy/` files and skip if pruned).

```bash
python -m pytest                  # 104 tests, ~0.3s
python -m pytest -v               # per-test names
```

Test files:

- `tests/conftest.py` — `guard` fixture + in-memory tarball builders. Note: the worm-string fixture puts the marker in CODE not a `//` comment (v2.4 strips comments before matching).
- `tests/test_patterns.py` — `scan_text` exemplars (one per MALICIOUS_PATTERNS entry — adding a pattern without an exemplar fails the suite), dedup, ASCII-only Unicode-escape regression (§5.6).
- `tests/test_known_bad.py` — `KNOWN_BAD` shape (allows the v2.4 `advisories` key), `HIGH_VALUE_TARGETS` superset, `DAEMON_PATHS["windows"] == []` guard, `CREDENTIAL_FILES`.
- `tests/test_tarball.py` — `scan_tarball_bytes` payload-filename / worm-string / ASCII-obfuscation detection + i18n non-detection + robustness (binary/non-gzip/empty).
- `tests/test_finding.py` — v2.4 `Finding` dataclass (defaults, `__iter__` backward-compat, `to_dict()` schema keys, independent mutable default) + `_wrap_finding`.
- `tests/test_typosquatting.py` — `_levenshtein` distances + `check_typosquatting` HIGH/MEDIUM/None boundaries.
- `tests/test_lockfile.py` — `_lockfile_packages` v1 (nested) / v2-v3 (`packages` dict) normalisation.
- `tests/test_noise_filter.py` — `_distrib_noise_filter` per-path-class incl. the CRITICAL→MEDIUM non-exec-dir rule (regression guard for Pillow/pymongo/virtualenv).
- `tests/test_sentinel.py` — `_sentinel_wrap`/`_sentinel_strip` round-trip + multi-block + idempotence (regression guard for `--unprotect`).
- `tests/test_json_schema.py` — `--json` schema validation (top-level + Finding keys, exit-code mapping, advisory enrichment, tuple normalisation) without network.

**Adding a pattern**: add a matching entry to `tests/test_patterns.py::EXEMPLARS` or `test_each_pattern_has_an_exemplar` fails (intentional).

Still open (P1 in `docs/SECURITY_REVIEW.md §8`): a fuzz harness on `scan_text` / `scan_tarball_bytes` / `_lockfile_packages`; a sandboxed `tests/test_protect.py` exercising the full `--protect`→`--unprotect` filesystem round-trip.

### 8.2 Linter / formatter — `ruff` ✅ DONE

`ruff` configured in `pyproject.toml`. Full explainer at `docs/RUFF.md`.

```bash
python -m ruff check .                 # report
python -m ruff check . --fix           # auto-fix the safe ones
python -m ruff format .                # format
```

Selected rule groups: `E F W I B UP S C4 SIM RET`. The `S` (bandit-equivalent security) group is on because this is a security tool.

Deliberate ignores: `S603`, `S607`, `S310`, `S324`, `E501`, plus `S110` / `SIM105` / `SIM102` — best-effort `try/except/pass` is an architectural choice (a forensic scan must not crash on one unreadable file, §5.8), and the two `SIM` rules are style. Reasoning is in the comment above each in `pyproject.toml`. The archived `legacy/` tree is excluded from linting (unmaintained, §1), and `benchmarks/` has a small per-file-ignore (`assert` + typing/f-string parity).

**`ruff check .` exits 0** (clean) — this is what CI enforces. Earlier the command reported residual findings; they are now either fixed (unused loop vars, ambiguous name, env-var casing, import order) or documented-ignored. Keep it at zero: if a change adds a finding, fix it or add a justified ignore in the same commit.

### 8.3 Build / packaging — PyInstaller ✅ DONE

Single `.py` file *and* prebuilt single-file binary via PyInstaller:

```bash
python build.py            # build → dist/shai_hulud_guard[.exe] (prints sha256)
python build.py --clean    # rm -rf build/ dist/ *.spec
```

The canonical artefact is the source `.py` file; the binary is convenience.
`build.py` builds **only** the canonical `shai_hulud_guard.py` (the old `--v1`/`--v2`
split + the dead `"shai_hulud_guard V2.0.py"` path were removed); `build.ps1` and the
`Makefile` were updated in lockstep. The release workflow consumes this script.

### 8.4 Git state

- `.gitignore` — Python build/cache, venv, PyInstaller `dist/` `build/` `*.spec`, runtime-generated reports (`shai_hulud_report_*.txt`, `shai_hulud_pin_actions.txt`, `npm_safe_install.py`), editor junk, OS junk, `.env*`, `.claude/`.
- `.gitattributes` — LF for source, CRLF for `.bat`/`.ps1`, binary blobs marked binary.
- **Commit signing — SSH (repo-local).** `gpg.format=ssh`, `commit.gpgsign=true`, `tag.gpgsign=true`; signing key `~/.ssh/id_ed25519_shguard(.pub)` (signing-only, no passphrase for non-interactive commits); local verification via `~/.ssh/allowed_signers`. Committer email is the auto-verified GitHub noreply, so commits show **Verified** on GitHub. Commits `0be0733/cdd134a/f3e2c4c` predate signing and stay unsigned by design (rewriting them would break the hashes referenced across the docs); every commit from the productionisation commit onward is signed.
- Branches: `release/v2.4.0` (productionised line) merged `--no-ff` into `main`; signed annotated tag **`v2.4.0`**.
- **Remote — PUBLIC GitHub repo** `FractalRecursion/shai-hulud-guard` (public, for the portfolio/recruiter goal — **supersedes the earlier "private" instruction**).

**Project TODO — prioritised, numbered (user-requested features first, then release hardening):**

1. **⭐ CRITICAL — one-command removal of infected packages (`--remove`).** After `--scan` finds infection, remove it safely in ONE command. Thin orchestrator over existing `run_scan`/`classify_infection`/`generate_remediation`/`_write_cleanup_script`/`_write_daemon_script`. **Load-bearing safe order:** (1) remove persistence daemon FIRST (§5.2 kill-switch wipes `~/`), (2) remove infected packages by **deleting `node_modules/<pkg>` directly** / `pip uninstall -y` — for npm use `--ignore-scripts` so a malicious uninstall hook can't execute (§5.1), (3) delete payload files, (4) NEVER auto-revoke creds — print the manual rotation checklist after, (5) audit/rebuild guidance. Add `run_remove()` near `run_patch` (~L2584) + `--remove` in `main()`; `tests/test_remove.py`. Full design in `docs/SESSION_STATE.md §5`. **Pre-reqs that land first (the "before `--remove`" work): (a) convert `_execute_cmds` + the `generate_remediation` auto-path from `shell=True` → list-form argv (§5.8; injection-proof; add `--ignore-scripts`) so `--remove` inherits a safe executor — supersedes the old "reuse `_execute_cmds`" note; (b) F1 reversed-marker pattern (catch the reversed `Shai-Hulud` marker the antv `_indicators` documents).** **✅ Pre-reqs (a)+(b) DONE & validated (ruff clean · pytest 104 · self-test 6/6).** **Default posture (decided): dry-run preview; `--apply` to execute. npm-first (PyPI follow-up). Full build handoff: `docs/HANDOFF_REMOVE.md`.**
2. **Local-file / installer scanner** — new `--scan-file <path>` mode to vet an already-downloaded artifact (`.tgz`/`.whl`/`.zip`/`.tar.gz`, best-effort on installers/scripts) *before* opening it. Reuse `scan_tarball_bytes`/`scan_wheel_bytes`/`scan_text`; preserve never-execute (§5.1).
3. **P0 — Commit/release signing.** ✅ SSH commit + tag signing DONE (see git state above); release artifacts carry SLSA build-provenance via `release.yml`. ☐ **GPG signing (learning goal):** learn + enable GPG commit/tag signing and compare the SSH vs GPG vs Sigstore trust models.
4. **P0 — `.github/workflows/ci.yml`** ✅ DONE — matrix `os: [ubuntu, windows, macos] × py: [3.8, 3.10, 3.12]`, SHA-pinned actions, `ruff check . && pytest && --self-test`. Badge turns green on first push.
5. **P0 — `.github/workflows/release.yml`** ✅ DONE — on tag `v*`: per-OS PyInstaller build + `SHA256SUMS` + SLSA build-provenance attestation; Release published via `gh`.
6. **P0 — Public GitHub repo + push** (Phase B): `gh auth login` (human-gated) → register SSH key as a *signing* key (`gh ssh-key add --type signing`) → `gh repo create shai-hulud-guard --public --source . --remote origin --push` → enable branch protection on `main` (require CI) + repo topics.
7. **P1 — Fuzz harness** on `scan_text`/`scan_tarball_bytes`/`_lockfile_packages`; `tests/test_protect.py` filesystem round-trip. *(KNOWN_BAD advisory population ✅ DONE — OSV-sourced GHSA IDs + `tools/refresh_advisories.py`.)*
8. **P2 — Enterprise directions:** SARIF output (findings in the GitHub Security tab), publish as a reusable GitHub Action / pre-commit hook, SBOM (CycloneDX/SPDX) ingestion, PyPI maintainer-drift heuristic.
9. **Housekeeping:** ruff residual-cleanup PR. *(QUICKSTART→v2.4 ✅ DONE; OPEN-2 maintainer-scoring mismatch ✅ FIXED; matplotlib FP & subprocess split ✅ DONE — see DESIGN §2.9.)*
10. **F2+F3 — externalize IOC data → versioned `threat_intel/*.json` with a structured `_indicators` block** *(after `--remove`; derived from perplexityai/bumblebee).* Move `KNOWN_BAD`/`MALICIOUS_PATTERNS` into data files the scanner loads at startup (stdlib-only, schema-versioned). `_indicators` carries exfil host / preinstall cmd / decryptor global / markers (incl. reversed). Lets IOCs ship via PR without touching the scanner.
11. **F4 — `--exposure-catalog <path>` consumer** *(after `--remove`; depends on #10's schema).* Exact `(ecosystem, name, version)` match mode — a low-false-positive complement to the heuristics that can ingest bumblebee's own catalogs (interop).
12. **F5 — MCP-config + VS Code-extension inventory scan** *(after `--remove`).* New supply-chain surface (e.g. `nx-console-vscode`-style compromises). List presence/metadata only; **never emit `env`/credential values** (§5.3 / §5.11).
13. **`--scan-repo <url>` — remote-repo scan (⚠ PENDING USER GO/NO-GO).** Scan a Git repo by URL for Shai-Hulud IOCs. *Reuses* the scan engine (`scan_text`/`scan_tarball_bytes`/`_lockfile_packages`/`KNOWN_BAD`) but needs **new functions** (`_parse_repo_url`, `_repo_archive_url`, `run_scan_repo`) **and a §5.4 relaxation** to fetch read-only source archives from `codeload.github.com`/GitLab. Recommended design: fetch source tarball → scan **in memory** (never clone/extract/`npm install`/execute — §5.1); add an explicit host allowlist to `fetch_bytes` at the same time.
14. **QUICKSTART overhaul (accessibility-first, golden-standard).** (a) command×function table aggregated by use case; (b) per-use-case **time-ordered** table (recommended run order + what each step does); (c) plain-text install guide + copy-paste snippets. Technical yet readable for a new learner.
15. **Cognitive-accessibility statement of intent (user-authored doc).** A statement on neurodivergence + openness to new learners — an ethical principle / statement of intent. User crafts the prose; track submission + link it from README/QUICKSTART.

### 8.5 Documentation surface

- `docs/THREAT_MODEL.md` — Wave 1-5 attack chain → which v2.4 check/pattern/mode catches each step.
- `docs/DESIGN.md` — Invariants, trade-offs (incl. §2.5 non-exec-dir demotion), non-goals.
- `docs/JSON_SCHEMA.md` — `--json` schema, with an LLM-paste-ready example.
- `docs/SECURITY_REVIEW.md` — framework-driven (NIST CSF 2.0 / SSDF, OpenSSF Scorecard, OWASP CICD-SEC, SLSA, MITRE ATT&CK, CWE) final review + scored assessment + prioritised roadmap.
- `docs/RUFF.md` — ruff rule-group explainer.
- `docs/SESSION_STATE.md` — point-in-time session handoff (verbatim detection logic, calibration numbers, open issues, exact next action). Snapshot as of commit `cdd134a`; may go stale — trust the code + this CLAUDE.md over it if they diverge.
- `benchmarks/run_calibration.py` + `BENCHMARKS.md` — live-registry top-50 npm + top-50 PyPI scoring, **pinned to stable versions** for reproducibility (no publish-age noise).

### 8.6 CI / GitHub workflows & community files ✅ NEW

All GitHub Actions are **SHA-pinned** (not tag-pinned) — dogfooding the action-poisoning defence the tool itself detects; Dependabot bumps the pins.

- `.github/workflows/ci.yml` — matrix CI (ruff + pytest + `--self-test`); macOS 3.8 covered via the `macos-13` Intel runner (arm64 `macos-latest` has no 3.8).
- `.github/workflows/release.yml` — tag-triggered per-OS build + `SHA256SUMS` + SLSA build-provenance (`actions/attest-build-provenance`); Release via `gh`.
- `.github/workflows/codeql.yml` — CodeQL code scanning (python, `security-and-quality`).
- `.github/workflows/scorecard.yml` — OpenSSF Scorecard (`publish_results: true` → README badge + SARIF to code-scanning).
- `.github/dependabot.yml` — weekly `github-actions` + `pip`(dev) update PRs.
- `.github/ISSUE_TEMPLATE/{bug_report,ioc_report,feature_request}.yml` + `config.yml` — the IOC template enforces the §4.7 cited-source rule; `config.yml` routes vulns to private reporting.
- `.github/PULL_REQUEST_TEMPLATE.md` — checklist mirrors the §5 invariants + the calibration gate.
- `.github/CODEOWNERS`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`.
- README badges: live CI / CodeQL / OpenSSF Scorecard / latest-release (the old hardcoded "self-test 6/6" badge was removed in favour of the live CI badge).

---

## 9. Quick reference — most common edits

| You want to … | File / location |
|---|---|
| Add a new IOC regex | `MALICIOUS_PATTERNS` near top of `shai_hulud_guard.py`. Cite source in comment. Add an exemplar to `tests/test_patterns.py::EXEMPLARS`. |
| Add a known-bad version | `KNOWN_BAD`. Include `advisories: ["GHSA-…"]` if a public advisory exists. |
| Mark a new package as high-scrutiny | `KNOWN_BAD[name] = {"bad": [], "waves": [...], "advisories": []}`. Auto-flows into `HIGH_VALUE_TARGETS`. |
| Add a daemon persistence path | `DAEMON_PATHS[<plat>]`. Per-OS — make sure the path is correct on the target OS. |
| Add a new credential file to *check presence of* | `CREDENTIAL_FILES`. Never read it. |
| Add a new `--protect` modification | A new `_setup_*()` function. **Must** use `_sentinel_wrap()` for any file edits to allow `--unprotect` reversal. |
| Touch network code | `fetch_json()` / `fetch_bytes()`. Must remain stdlib-only and limited to npm/PyPI hosts (see §5.4). |
| Add a typosquatting target | Append to `_TOP_NPM_PACKAGES`. Keep the list focused on packages with ≥ 10M weekly downloads; small packages are noise. |
| Update the incident guide | `run_incident()`. Preserve the 8-step ordering — see §5.7. |
| Add an exit code | `main()` dispatch. Currently `0` and `1` only. Document any addition in §2. |
