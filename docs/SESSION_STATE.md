# SESSION STATE — shai_hulud_guard (handoff for context reset)

> Authoritative resume document. Everything needed to continue without error is
> here or in the repo. Project root: **`C:\Users\Utente\Shai_Hulud_Guard\`**.
> Do NOT look outside that directory. The file at `C:\Users\Utente\shai_hulud_guard.py`
> is a **v2.3.0 backup — never modify it.**

---

## 0. CURRENT STATE & EXACT NEXT ACTION

- **Phase:** ALL planned phases (0,1,3,4,5A,5B,5C,6) + the framework-review deliverable are **COMPLETE and committed.**
- **Git:** branch **`release/v2.4.0`**, commit **`cdd134a`** (27 files, +7796/−1148). Working tree **clean**. `main` is the prior commit `0be0733` (untouched). **Nothing pushed** (no remote yet).
- **Validation (last run, all green):** `--self-test` 6/6 · `pytest` **101 passed** · benchmark **exit 0** (thresholds held) · ruff **19** (all pre-existing, none security-relevant) · no hardcoded paths · version 2.4.0 consistent across source/pyproject/`--version`.

**EXACT NEXT ACTION (pick one, user decides):**
1. **Merge** `release/v2.4.0` → `main` (`git checkout main && git merge --no-ff release/v2.4.0`), OR keep on branch for PR.
2. **P0 roadmap** (from `docs/SECURITY_REVIEW.md §8`, highest-leverage first):
   - P0-1: sign commits + releases (Sigstore/cosign + PGP) — advances OpenSSF Scorecard Signed-Releases, NIST SSDF PS.1/PS.2, SLSA L0→L2 at once.
   - P0-2: `.github/workflows/ci.yml` — matrix `python: [3.8,3.10,3.12]` × `os: [ubuntu,macos,windows]` running `ruff check . && pytest && python shai_hulud_guard.py --self-test`.
   - P0-3: `.github/workflows/release.yml` — on tag, `python build.py` + SLSA provenance + SHA-256 checksums.
3. **Push private GitHub repo** — BLOCKED in prior session: `gh` not on Git Bash PATH. Workaround: run via PowerShell tool — `gh repo create shai-hulud-guard --private --source . --remote origin --push`. **Re-verify `--private`** before Enter.

**This document itself:** when out of plan mode, also save it as `docs/SESSION_STATE.md` in the repo and commit (it currently lives only in `.claude/plans/quiet-wiggling-fairy.md`).

---

## 1. PROJECT IDENTITY

- **What:** `shai_hulud_guard.py` v2.4.0 — single-file, **stdlib-only**, cross-platform (Win/macOS/Linux), Python 3.8+ CLI that detects/removes/prevents the **Shai-Hulud npm+PyPI supply-chain worm** and adjacent supply-chain attacks.
- **Size:** 3803 lines. **License:** GPL-3.0. **Runtime deps: ZERO** (hard invariant).
- **Dual purpose:** (a) a defensive scanner; (b) an OSS project that is itself a supply-chain link → both need security rigor.

### Repo layout
```
shai_hulud_guard.py            canonical v2.4.0 (3803 lines)
CLAUDE.md                      agent handoff / invariants / IOC sources (READ FIRST when editing)
README.md  QUICKSTART.md       user docs (QUICKSTART still describes v2.0 — TODO update)
CHANGELOG.md  LICENSE  SECURITY.md
BENCHMARKS.md                  calibration snapshot (verbatim numbers in §7)
pyproject.toml                 version 2.4.0, GPL-3.0, ruff+pytest config, deps=[]
build.py  build.ps1  Makefile  PyInstaller build
benchmarks/run_calibration.py  live-registry FP/TP benchmark (pinned versions)
docs/THREAT_MODEL.md           wave 1-5 attack chain → detections
docs/DESIGN.md                 invariants, trade-offs, non-goals
docs/JSON_SCHEMA.md            --json schema + LLM-paste example
docs/SECURITY_REVIEW.md        framework-driven final review (NIST/OpenSSF/OWASP/SLSA/ATT&CK/CWE)
docs/RUFF.md                   ruff explainer
legacy/                        archived, UNMAINTAINED: v1.1 + v2.0 + README
tests/                         101 pytest tests (9 files + conftest)
.claude/settings.local.json    permissions (gitignored)
```

---

## 2. IMPLEMENTATION PLAN — COMPLETED vs REMAINING

### COMPLETED (all committed in cdd134a)
| Phase | What | Where |
|---|---|---|
| 0 | Permissions auto-allow safe ops | `.claude/settings.local.json` |
| 1 | Reconcile: v1.1+v2.0 → `legacy/`, install v2.3→canonical, bump 2.4.0, gh-token-monitor comment, LICENSE/SECURITY/CHANGELOG/.gitignore | repo root |
| 3 | `Finding` dataclass + `_wrap_finding`; `collect_system_info`+`generate_diagnosis_report`+`run_diagnose` (`--diagnose`); `advisories:[]` scaffold on KNOWN_BAD | `shai_hulud_guard.py` |
| 4 | pytest rewrite to single `guard` fixture + 5 new test files = **101 tests** | `tests/` |
| 5A | `--json` mode + `docs/JSON_SCHEMA.md` | `shai_hulud_guard.py`, docs |
| 5B | `docs/THREAT_MODEL.md`, `docs/DESIGN.md` | docs |
| 5C | `benchmarks/run_calibration.py` + `BENCHMARKS.md`; **calibration FP fixes** (see §6/§8) | benchmarks, source |
| 6 | Final validation roundtrip | — |
| NEW | `docs/SECURITY_REVIEW.md` framework review | docs |

### REMAINING (none required for v2.4 correctness; all are release-hardening)
- Save `docs/SESSION_STATE.md` (this doc) + commit.
- Merge branch → main (or open PR).
- P0: signing, repo CI, release provenance (see §0).
- P1: fuzz harness on `scan_text`/`scan_tarball_bytes`/`_lockfile_packages`; populate `KNOWN_BAD["advisories"]` with real GHSA IDs; `tests/test_protect.py` filesystem roundtrip.
- P2: SBOM ingestion; PyPI maintainer-drift heuristic; optional behavioral-analysis API hook.
- Housekeeping: update `QUICKSTART.md` to v2.4; resolve the maintainer-removed scoring discrepancy (§9 OPEN-2).

---

## 3. MODES & FUNCTION/LINE MAP (shai_hulud_guard.py)

CLI dispatch in `main()` (line 3682). Flags: `--scan --path --check --check-pypi --lockcheck --patch --auto --verify --self-test --protect --unprotect --install-hook --setup-alias --setup-npmrc --setup-cron --diagnose --json --incident --version`.

**Exit codes:** `0` = clean / no critical; `1` = `--check`/`--check-pypi` risk≥40 (used by wrapper scripts to block install). `--json` mode: exit code embedded in JSON AND returned by process; suppresses `sys.exit(1)` mid-run so JSON still emits.

Key functions (line → purpose):
- 291 `_levenshtein`, 306 `check_typosquatting`
- 388 `Finding` (dataclass), 404 `_wrap_finding`
- 465 `_json_mode_enter`, 473 `_json_mode_exit_and_emit`, 486 `_json_record_mode_result`
- 534-542 output helpers `ok/warn/crit/info/head/subh/dim` (ANSI via `_c`)
- 549 `fetch_json` (12s), 561 `fetch_bytes` (45s) — **stdlib urllib only**
- 573 `scan_text`, 590 `scan_tarball_bytes` (.tgz, in-memory), 626 `_strip_comments`, 689 `_distrib_noise_filter`
- 749 `_prev_version_npm`, 779 `_parse_semver`, 786 `check_maintainer_change`, 820 `check_version_gap`, 853 `check_new_dependencies`
- 888 `fetch_pypi_meta`, 898 `scan_wheel_bytes` (.whl zip), 922 `_check_pip_packages`
- 953 `run_pypi_check`, 1262 `_lockfile_packages`, 1285 `scan_lockfile`, 1366 `check_windows_persistence`
- 1400 `classify_infection`, 1430 `_execute_cmds`, 1448 `_execute_ps`, 1464 `_write_daemon_script`, 1528 `_write_cleanup_script`, 1609 `generate_remediation`
- 1744 `run_scan` (8 checks), 2044 `run_check` (5 steps + 2.5), 2395 `run_incident`, 2482 `run_lockcheck`, 2584 `run_patch`, 2720 `run_verify`, 2745 `run_self_test`
- 2891 `_sentinel_wrap`, 2895 `_sentinel_strip`, 2905-3058 `_write_npm/pip_wrapper`/`_write_ci_workflow`/`_write_githook_template`, 3090 `_install_git_hook`, 3111 `_shell_profile`, 3135 `_setup_shell_alias`, 3169 `_setup_project_npmrc`, 3187 `_setup_scheduled_scan`, 3230 `run_unprotect`, 3338 `run_protect`
- 3462 `collect_system_info`, 3524 `generate_diagnosis_report`, 3620 `run_diagnose`, 3682 `main`

---

## 4. DETECTION LOGIC — VERBATIM

### 4.1 MALICIOUS_FILENAMES (hard-block by basename, any content)
```python
{ "router_init.js", "setup_bun.js", "bun_environment.js", "setup.mjs" }
```
Rationale: exact files the worm drops. `router_init.js` = ~2.3 MB obfuscated core payload (all waves); `setup_bun.js` = Bun installer stub (waves 2+); `bun_environment.js` (wave 2); `setup.mjs` ESM variant (wave 1).

### 4.2 MALICIOUS_PATTERNS (45 entries) — VERBATIM `(regex, desc, risk)`
risk ∈ {CRITICAL,HIGH,MEDIUM,LOW}. Matched case-insensitively by `scan_text`; `_strip_comments` runs FIRST on source files.

```python
# Worm identity markers
(r"Sha[i1].?Hulud|Shai.?Hulud",              "Worm identity string",                       "CRITICAL"),
(r"Here We Go Again|The Second Coming",       "Worm campaign tag",                          "CRITICAL"),
(r"TeamPCP|DeadCatx3|PCPcat|ShellForce|CipherForce", "Known threat actor marker",          "CRITICAL"),
(r"gh.?token.?monitor",                       "Persistent token-monitor daemon name",       "CRITICAL"),
(r"A Mini Shai.?Hulud has Appeared",          "Worm repo description tag",                  "CRITICAL"),
# Destructive payload — home-ROOT wipe only (NOT ~/subdir)
(r"rm\s+-rf\s+[\"']?~(?:/?[\"'\s]|/?$)|rm\s+-rf\s+\$(?:HOME|USERPROFILE|USER\b)(?:[\s\"']|/?$)",
                                              "Linux/macOS home-directory wipe",           "CRITICAL"),
(r"Remove-Item\s+.*-Recurse.*Home|rmdir\s+/s\s+/q\s+.*%USERPROFILE%",
                                              "Windows home-directory wipe",               "CRITICAL"),
# Exfiltration infrastructure
(r"git-tanstack\[?\.\]?com|git-tanstack\.com","Known C2 typosquat domain",                 "CRITICAL"),
(r"webhook\.site\/[a-f0-9\-]{36}",            "Known exfiltration endpoint (webhook.site)","CRITICAL"),
(r"getsession\.org|signal\.org|oxen\.io",     "Session network (C2 exfiltration channel)", "HIGH"),
# Credential file targeting
(r"application_default_credentials\.json",    "GCP credential file access",                "HIGH"),
(r"\.aws[/\\]credentials",                    "AWS credential file path referenced",       "HIGH"),
(r"AWS_SECRET_ACCESS_KEY[^\w].{0,60}(?:curl|fetch|requests?\.|http|urllib|send|post|put)\b"
 r"|(?:curl|fetch|requests?\.|http|urllib|send|post|put).{0,60}AWS_SECRET_ACCESS_KEY",
                                              "AWS credentials in HTTP request context (exfiltration signal)", "CRITICAL"),
(r"AZURE_CLIENT_SECRET|AZURE_TENANT_ID|azure_credentials", "Azure credential access",      "HIGH"),
(r"\.ssh[/\\](?:id_rsa|id_ed25519|id_ecdsa)\b|[\"'`~]\.ssh[/\\]", "SSH key file path access (.ssh/ prefix)", "HIGH"),
(r"(?:readFile|read_text|open|fs\.[rs]|cat\s+)[^\n]{0,60}\.npmrc|\.npmrc[^\n]{0,40}(?:_authToken|_auth\s*=)",
                                              ".npmrc credential file read",               "HIGH"),
# Token literals
(r"ghp_[A-Za-z0-9]{36}",                      "GitHub PAT literal in code",                "CRITICAL"),
(r"gho_[A-Za-z0-9]{36}",                      "GitHub OAuth token literal",                "CRITICAL"),
(r"npm_[A-Za-z0-9]{36}",                      "npm token literal",                         "CRITICAL"),
# Bun runtime substitution
(r"bun\.sh/install|curl.*bun\.sh|install.*bun\.sh|bunx\b", "Bun runtime installer in lifecycle script", "HIGH"),
(r"\"bun\"\s*,?\s*\"run\"|spawn.*bun\b",      "Bun used to execute payload",               "HIGH"),
# OIDC / CI token extraction
(r"/proc/\d+/mem|\bptrace\s*\(|\bprocess_vm_readv\b", "CI runner memory extraction",       "CRITICAL"),
(r"ACTIONS_ID_TOKEN_REQUEST_URL|ACTIONS_ID_TOKEN_REQUEST_TOKEN", "GitHub OIDC token ENV var access", "HIGH"),
(r"id[-_]token['\"]?\s*:\s*['\"]?\s*write|id[-_]token['\"]?\s*:[^\n]{0,30}permissions",
                                              "OIDC id-token scope in config",             "MEDIUM"),
# Persistence
(r"LaunchAgents.*com\.user\.",                "macOS LaunchAgent persistence",             "CRITICAL"),
(r"systemd/user.*\.service",                  "Linux systemd user service persistence",    "CRITICAL"),
(r"SCHTASKS|schtasks\.exe",                   "Windows Task Scheduler persistence",        "HIGH"),
# Obfuscation
(r"atob\s*\(\s*['\"][A-Za-z0-9+/=]{40,}['\"]|Buffer\.from\s*\(\s*['\"][A-Za-z0-9+/=]{40,}['\"],\s*['\"]base64['\"]",
                                              "Base64-encoded payload literal (obfuscation signal)", "HIGH"),
(r"eval\s*\(\s*(atob|Buffer|decodeURI)",      "eval of decoded content",                   "HIGH"),
(r"(?:\\u00[2-7][0-9a-fA-F]){4,}",            "ASCII chars encoded as \\u escapes (obfuscation)", "MEDIUM"),
# GitHub API abuse
(r"api\.github\.com/user/repos",              "GitHub API repo creation (credential dump)","HIGH"),
(r"[\"']Authorization[\"']\s*:\s*[\"']Bearer\s+\$|[\"']Authorization[\"'].*\+.*token\b",
                                              "Authenticated GitHub API call (auth header construction)", "MEDIUM"),
# Cache poisoning
(r"pull_request_target",                      "pull_request_target trigger (only dangerous with cache — see CHECK 6)", "LOW"),
(r"actions/cache.*restore-keys",              "Cache restore with broad key (potential poison)", "LOW"),
# Ported from Node scanner
(r"nc\s+-[el]|socat\s+.*exec|bash\s+-i\s+>&", "Reverse shell command",                     "CRITICAL"),
(r"wget\s+-q\s+http|curl\s+-s[SO]?\s+http",   "Silent file download (exfiltration signal)","HIGH"),
(r"\/etc\/passwd|\/etc\/shadow",              "System credential file access",             "HIGH"),
(r"(?<!\w)\.env(?!\w)",                       ".env file access",                          "MEDIUM"),
(r"\bexec\s*\(\s*[\"'`][^\"'`]{4,}",          "Shell exec with string literal",            "MEDIUM"),
# Python / PyPI specific
(r"subprocess\.\w+\s*\(\s*\[?\s*['\"](?:curl|wget|bash|sh|powershell|cmd\.exe)",
                                              "Subprocess spawning downloader/shell in package", "HIGH"),
(r"os\.system\s*\(\s*['\"](?:curl|wget|rm\s+-rf|del\s+/|bash\s+-[ci])",
                                              "os.system with dangerous command in setup", "CRITICAL"),
(r"__import__\s*\(\s*['\"]os['\"]",           "Dynamic os import (obfuscation pattern)",   "HIGH"),
(r"atexit\.register\s*\(",                    "atexit hook registered (check if in setup/install script)", "LOW"),
(r"cmdclass\s*=\s*\{",                        "Custom setup cmdclass override (setup.py lifecycle hook)", "MEDIUM"),
(r"\.pth\b.*(?:import|exec|__)",              ".pth file with code injection",             "CRITICAL"),
```

### 4.3 KNOWN_BAD (verbatim) — `{name: {bad, waves, advisories}}`
```python
"@tanstack/react-router": {"bad": ["1.169.5"], "waves": ["Wave5-May2026"], "advisories": []},
"@tanstack/router":       {"bad": ["1.169.5"], "waves": ["Wave5-May2026"], "advisories": []},
"@tanstack/react-query":  {"bad": [],          "waves": ["Wave5-May2026"], "advisories": []},
"@mistralai/mistralai":   {"bad": [],          "waves": ["Wave5-May2026"], "advisories": []},
"@uipath/apollo-core":    {"bad": [],          "waves": ["Wave5-May2026"], "advisories": []},
"guardrails-ai":          {"bad": ["0.10.1"],  "waves": ["Wave5-May2026"], "advisories": []},
"mistralai":              {"bad": ["2.4.6"],   "waves": ["Wave5-May2026"], "advisories": []},
"@bitwarden/cli":         {"bad": [],          "waves": ["Wave4-Apr2026"], "advisories": []},
"intercom-client":        {"bad": ["7.0.4"],   "waves": ["Wave5-May2026"], "advisories": []},
"gh-token-monitor":       {"bad": [],          "waves": ["Wave1-Sep2025","Wave5-May2026"], "advisories": []},  # daemon NAME, not a pkg
"tinycolor2":             {"bad": [],          "waves": ["Wave1-Sep2025"], "advisories": []},
"@asyncapi/cli":          {"bad": [],          "waves": ["Wave2-Nov2025"], "advisories": []},
```
`bad:[ver]` → confirmed malicious version, hard-block risk=100. `bad:[]` → watchlist, +15 + MEDIUM. **advisories all empty (scaffold)** — population deferred (P1).

### 4.4 HIGH_VALUE_TARGETS = KNOWN_BAD.keys() ∪
```python
{ "@tanstack/form","@tanstack/table","@tanstack/virtual","@tanstack/store",
  "@tanstack/start","@tanstack/query-core","@squawk/core","@opensearch-project/opensearch" }
```

### 4.5 DAEMON_PATHS (persistence) — `Path.home()` relative
```python
linux:   ~/.config/systemd/user/gh-token-monitor.service
darwin:  ~/Library/LaunchAgents/com.user.gh-token-monitor.plist
windows: []   # INTENTIONALLY EMPTY — no public path; detected dynamically
```
WINDOWS_TASK_KEYWORDS (Task Scheduler + Startup folder scan):
`("gh-token-monitor","github-token-monitor","npm-helper","bun-helper","node-updater")`

### 4.6 CREDENTIAL_FILES (presence ONLY — never read contents, §5.3)
`~/.npmrc, ~/.gitconfig, ~/.config/gcloud/application_default_credentials.json, ~/.aws/credentials, ~/.ssh/id_rsa, ~/.ssh/id_ed25519, ~/.ssh/id_ecdsa`

### 4.7 Typosquatting: `_TOP_NPM_PACKAGES` (≈108 names), Levenshtein ≤2 → HIGH(d=1)/MEDIUM(d=2); exact match → None. Scoped names use bare name. Fast filter: skip if `abs(len diff) > 3`.

---

## 5. RISK SCORING (verbatim weights) + NOISE FILTER + CLASSIFIER

### 5.1 run_check (npm, line 2044) scoring
- Publish age: `<6h`=+40, `<24h`=+25, `<7d`=+10 (lines 2133/2137/2141)
- Typosquat: HIGH=+15, MEDIUM=+5 (2160)
- KNOWN_BAD confirmed: +100 (2171, early-return path also at 2291 sets 100); watchlist/HVT: +15 (2176)
- STEP 2.5 (2188-2208): maintainer finding `+= 20 if HIGH else 10` (2192); version-gap `+= 20 if HIGH else 8` (2200); new non-registry dep `+= 15` each (2208)
- Lifecycle scripts (2231): `+45 CRITICAL / +20 HIGH / +8 else`; preinstall present +5 (2237)
- Git/file deps: `min(count*12, 30)` (2257)
- Tarball integrity mismatch: +100 (2291/2298). Large tarball **>1500 KB**: +10 (2310)
- Tarball findings (2326): `+50 CRITICAL / +20 HIGH / +4 else` (after `_distrib_noise_filter`)

### 5.2 run_pypi_check (line 953) scoring — parallel: publish age +40/+25/+10 (1048/52/56), confirmed +100 (1085, early-return 100 at 2291 npm-only), watchlist +15 (1090), git deps +30/+15/+5 (1112), integrity +100 (1156), setup hook +5 (1163), dist findings +50/+20/+4 (1191).

### 5.3 Verdict tiers (both checks)
`0`→proceed-with-caution · `1-14`→Low · `15-39`→Moderate · `40-69`→High (exit 1) · `≥70`→CRITICAL do-not-install.

### 5.4 `_distrib_noise_filter(filepath, risk)` (line 689) — FINAL logic
Precedence:
1. `is_setup` (basename in `_SETUP_FILES = {setup.py, pyproject.toml, setup.cfg, package.json, install.js, preinstall.js, postinstall.js}`) → return risk verbatim.
2. `in_noexec` (path contains any `_NOEXEC_DIRS` OR basename in `_NOEXEC_FILES`) → **CRITICAL→MEDIUM**, everything else→LOW (suppressed).
   - `_NOEXEC_DIRS` = `/test/ /tests/ /__tests__/ /spec/ /test_ /fixtures/ /mocks/ /stubs/ /.github/ /.circleci/ /.travis /appveyor /ci/ /.evergreen/ /.azure-pipelines/ /.buildkite/ /.gitlab/ /.teamcity/ /.azure/`
   - `_NOEXEC_FILES` = `azure-pipelines.yml(.yaml) .travis.yml(.yaml) appveyor.yml(.yaml) .gitlab-ci.yml(.yaml) .circleci.yml tox.ini noxfile.py conftest.py`
3. CRITICAL outside non-exec → passes through.
4. `_NOISE_DIRS` (`/doc/ /docs/ /_static/ /examples/ /demo/ /vendor/ /vendored/ /third_party/ /thirdparty/ /external/`) → HIGH→MEDIUM, MEDIUM→LOW; CRITICAL stays.
Caller drops LOW. **Same filter used by npm AND PyPI paths** (no inline copy).

### 5.5 classify_infection (line 1400) — exact branch order
```
daemon_found and (bad_pkg>0 or lockfile_critical>0) → FULL_COMPROMISE, DEFINITIVE
daemon_found                                        → DAEMON_ONLY, DEFINITIVE
bad_pkg>0 and lockfile_critical>0                   → PACKAGES_ONLY, HIGH
lockfile_critical>0                                 → LOCKFILE_TAMPERED, HIGH
bad_pkg>0                                           → PACKAGES_ONLY, HIGH
pattern_hits>=3                                     → LOW_CONFIDENCE, MEDIUM
pattern_hits>=1 or total_findings>=2                → UNCERTAIN, LOW
else                                                → CLEAN, DEFINITIVE
```

---

## 6. WORM SIGNATURE RATIONALE (mapped to behaviour) — from docs/THREAT_MODEL.md

Wave timeline: W1 Sep2025 (compromised maintainer creds, 500+ pkgs), W2 Nov2025 (CI/CD injection, 796 pkgs/1092 versions, `setup_bun.js`), W3 Mar2026 (Aqua/Trivy), W4 Apr2026 (SAP/Bitwarden), W5-Mini May2026 (GitHub Actions cache poison + OIDC extraction, 172 pkgs/403 versions/518M downloads, **valid SLSA-BL3 provenance on malicious packages**).

Attack chain → detection:
1. Fork→`pull_request_target`→poison Actions cache → CHECK 6 (pull_request_target+cache)
2. Cache restored by release workflow → downstream tarball signal
3. OIDC token from `/proc/<pid>/mem` → "CI runner memory extraction" CRITICAL
4. `preinstall` installs Bun → "Bun runtime installer" HIGH
5. `router_init.js` (~2.3MB) runs → MALICIOUS_FILENAMES hard-block
6. Sweeps npm/GitHub/AWS/GCP/Azure/SSH creds → credential-file patterns + CHECK 5 presence
7. Exfil via `git-tanstack[.]com` / Session network / GitHub dead-drops → C2 patterns
8. Stolen npm token publishes infected versions of ≤100 victim pkgs → KNOWN_BAD + publish-age weighting
9. Installs `gh-token-monitor` daemon (60s poll) → CHECK 1 / DAEMON_PATHS
10. **Kill switch:** token revocation → `rm -rf ~/` → "home-directory wipe" CRITICAL + the §5.2 invariant ordering

---

## 7. TEST RESULTS — EXACT NUMBERS

### 7.1 pytest: **101 passed in ~0.3–0.7s.** Files: test_patterns, test_known_bad, test_tarball, test_finding, test_typosquatting, test_lockfile, test_noise_filter, test_sentinel, test_json_schema + conftest. Fixture: single `guard` (loads root module), optional `legacy_v1`/`legacy_v2` (skip if pruned).

### 7.2 --self-test: **6/6** (synthetic temp-dir infection: daemon index.js, malicious postinstall, non-registry lockfile, router_init.js payload). Sandboxed, never executes.

### 7.3 Benchmark (BENCHMARKS.md, 2026-05-20 14:49 UTC, 105 live packages, 540.2s) — **exit 0, thresholds held**
- **npm:** mean **2.2/100**, median 0, max **16** (`cypress@13.7.1`). Non-zero npm: react/react-dom/semver/typescript/prettier/mocha=10, vite=12, cypress=16, dotenv=8, got/nodemon/playwright=4. All ≤25.
- **PyPI:** mean **6.5/100**, median 4, max **45** (`matplotlib==3.8.3`, AT boundary). Notable: numpy=37, sqlalchemy=29, pandas=20, click=20, scipy/scikit-learn/pillow/fastapi=13, pytest/coverage/alembic/vite=12, django=9, pymongo=8. All ≤45.
- **True-positive: 100%** — all 5 (@tanstack/react-router@1.169.5, @tanstack/router@1.169.5, intercom-client@7.0.4, guardrails-ai==0.10.1, mistralai==2.4.6) → **100/PACKAGES_ONLY/exit 1**.

### 7.4 Calibration thresholds (benchmarks/run_calibration.py)
`NPM_TOP_MEAN_MAX=10, NPM_TOP_INDIVIDUAL_MAX=25, PYPI_TOP_MEAN_MAX=15, PYPI_TOP_INDIVIDUAL_MAX=45, TP_RATE_MIN=1.0, PER_PACKAGE_TIMEOUT_S=60`. FP set = pinned stable versions (no publish-age noise, reproducible). TP set pinned to exact bad versions. Re-run: `python benchmarks/run_calibration.py --markdown > BENCHMARKS.md` (or `--quick` for npm top-10).

---

## 8. CALIBRATION FIXES APPLIED (the FPs the benchmark caught) — DO NOT REGRESS
| Package | Was | Now | Fix |
|---|--:|--:|---|
| pillow | 100 | 13-17 | home-wipe pattern bare-`~` only; test-dir demotion |
| vite | 68 | 12 | `\bptrace\s*\(` word boundary (was matching `depTrace`) |
| pymongo | 62 | 8 | `.evergreen/` added to `_NOEXEC_DIRS` |
| prettier | 30 | 10 | OIDC `id[-_]token`+bounded gap (was matching "Invalid token…write") |
| virtualenv | 55 | 5 | non-exec dir CRITICAL→MEDIUM (was →HIGH, accumulated) |
| matplotlib | 95 | 45 | "subprocess spawns shell" CRITICAL→HIGH; `azure-pipelines.yml` in `_NOEXEC_FILES` |
| react-dom | 30 | 10 | `_prev_version_npm` skips pre-releases; maintainer-added HIGH→MEDIUM; tarball threshold 800→1500 KB |

**Calibration philosophy (docs/DESIGN.md §2.5):** definitive-compromise signals (home wipe, C2 domains, token literals, reverse shells, /proc/pid/mem, worm identity) stay CRITICAL; suspicious-but-common signals that legit packages also exhibit (subprocess-spawns-shell, new maintainer, large tarball, patterns in test/CI dirs) are weighted to surface-not-hard-block. Asymmetry rule (§5.9): be conservative on `--check` (FP cheap), precise on `--scan` (FP can make a victim wipe a clean machine).

---

## 9. SECURITY DO/DON'T (CLAUDE.md §5 invariants) + OPEN ISSUES

### NEVER (each prevents irreversible harm):
- **§5.1** Never execute target code. Tarballs/wheels read in-memory (`extractfile`/`zf.read`), never `extractall`/`exec`/`eval`/`node`/`bun`.
- **§5.2** Never auto-revoke/rotate credentials. Daemon's kill switch wipes `~/` on revocation. Rotation is a PRINTED manual checklist, done AFTER daemon removal.
- **§5.3** Never read credential file CONTENTS — presence/path only.
- **§5.4** Never phone home. Outbound HTTPS only to registry.npmjs.org + npm CDN + pypi.org + its release URLs. No telemetry.
- **§5.5** Every new pattern/KNOWN_BAD entry needs a cited public source (GHSA→NVD→OSV→Datadog→CISA→Wiz→StepSecurity, CLAUDE.md §4.7).
- **§5.6** Unicode-escape pattern stays ASCII-scoped `\u002X-\u007X` (broadening floods i18n libs).
- **§5.7** Incident guide order is load-bearing: STOP→ISOLATE→IMAGE→REMOVE DAEMON→ROTATE→AUDIT→REBUILD→REPORT.
- **§5.8** No `subprocess(shell=True)` except the documented `_execute_cmds` remediation (noqa S602). Use list form.
- **§5.10** Every `--protect` file mod is wrapped in sentinels `# === shai-hulud-guard … === /shai-hulud-guard ===`; `_SHAI_START`/`_SHAI_END` strings are versioned-stable — **never rename** (orphans existing installs).
- **§5.11** `--diagnose`/`--json` emit NO credential values, env values, or file contents (only 100-char match snippets). Guarded by `tests/test_json_schema.py`.
- **Stdlib only** — never add a runtime dependency.

### OPEN ISSUES / EDGE CASES (precise)
- **OPEN-1 — matplotlib==3.8.3 = 45 (exactly at PyPI threshold).** Passes (check is `>45`) but fragile: one more MEDIUM in a future version breaches. Composition: `setupext.py` subprocess HIGH + 3 MEDIUM. Legit (native-ext build). If it breaches later: consider `tools/` as a soft-noise dir, or accept + raise threshold to 50 with rationale.
- **OPEN-2 — maintainer-removed scoring doc/code mismatch.** `check_maintainer_change` returns "LOW" for removed maintainer, but `run_check` STEP 2.5 wiring (line 2192) scores `+= 20 if HIGH else 10` → a removed maintainer adds **+10**, not +0 as CLAUDE.md §3 risk table states ("removed → +0 LOW"). Fix later: either make the wiring distinguish MEDIUM(+10)/LOW(+0), or correct the doc. Low impact (no benchmark package triggered removed-maintainer).
- **EDGE — `--json --scan`** populates only aggregate fields (risk_score/case/confidence); per-finding list is empty (run_scan emits inline-only). `--diagnose` and `--check`/`--check-pypi --json` give full structured findings. Documented in JSON_SCHEMA.md §Limitations. v2.5 enhancement.
- **EDGE — numpy==1.26.4 = 37, sqlalchemy==2.0.29 = 29.** Highest legit PyPI scores; under 45 but elevated (native-ext build subprocess HIGH + MEDIUMs). Honest, not FPs.
- **KNOWN FN class** (documented non-goal): novel obfuscation with zero overlap to W1-5 patterns → 0 findings; runtime-fetched-then-eval payloads where fetch+eval aren't both literal; pre-disclosure window (2-8h before IOC list updates). A zero score is NOT a clean guarantee.
- **ruff:** 19 residual (all pre-existing: S110×9 best-effort except-pass, B007×4, SIM102×3, E741, SIM105, SIM112). Intentional noqa: S602×1 (_execute_cmds), S103×7 (0o755 on generated exec scripts). Scoped as a future cleanup PR (CLAUDE.md §8.2).
- **QUICKSTART.md** still describes v2.0 — update for v2.4.

---

## 10. EVERY MODIFIED/ADDED FILE (commit cdd134a) + NATURE
**Modified (M):**
- `shai_hulud_guard.py` — v2.3→v2.4: Finding dataclass+JSON mode+diagnose; advisories scaffold; gh-token-monitor comment; all §8 calibration fixes; noise-filter restructure (`_NOEXEC_DIRS`/`_NOEXEC_FILES`); pattern tightening; schtasks shell=True→list; noqa annotations. VERSION 2.4.0.
- `CLAUDE.md` — rewritten for v2.4 single-file arch; §3 noise-filter+risk table; §8 test/roadmap/docs; preserved §5 invariants + §4.7 sources verbatim.
- `README.md` — rewritten for v2.4 (10 modes, calibration baseline, GPL).
- `pyproject.toml` — version 2.0.0→2.4.0, license MIT→GPL-3.0-or-later, keywords.
- `.gitignore` — added v2.4 generated artifacts (npm_safe/pip_safe/remove_daemon/clean_packages/shai_hulud_pre_commit.hook/shai_hulud_scan.log).
- `tests/conftest.py` — single `guard` fixture + `legacy_*`; worm-string fixture moved marker to code (comment-strip aware).
- `tests/test_patterns.py` — single fixture; EXEMPLARS for all 45 patterns; risk-level + dedup + ASCII-escape regression.
- `tests/test_known_bad.py` — allow `advisories` key; single fixture.
- `tests/test_tarball.py` — single fixture; dropped v2 duplicates.
- `tests/test_finding.py` — rewritten for v2.4 Finding (was v2.0 dataclass).

**Renamed (R):** `shai_hulud_guard V2.0.py` → `legacy/shai_hulud_guard_v2.0_interactive.py`.

**Added (A):** `BENCHMARKS.md, CHANGELOG.md, LICENSE (GPL-3.0), SECURITY.md, benchmarks/run_calibration.py, docs/{DESIGN,JSON_SCHEMA,SECURITY_REVIEW,THREAT_MODEL}.md, legacy/{README.md, shai_hulud_guard_v1.1.py}, tests/{test_json_schema,test_lockfile,test_noise_filter,test_sentinel,test_typosquatting}.py`.

**Pre-existing tracked files (from initial commit 0be0733, unchanged in cdd134a):** `QUICKSTART.md`, `docs/RUFF.md`, `.gitattributes`, `Makefile`, `build.py`, `build.ps1`. **Gitignored (never committed):** `.claude/` (local permissions). Working tree is **clean** (verified).

---

## 11. FRAMEWORK REVIEW SUMMARY (docs/SECURITY_REVIEW.md)
7 frameworks: NIST CSF 2.0 (5/6 functions strong, Govern partial), NIST SSDF (PW.4 zero-dep exemplary; PS.1/PS.2 signing gap), OpenSSF Scorecard (content checks strong; Signed-Releases=0, CI-Tests/Branch-Protection/Fuzzing gaps), OWASP CICD-SEC (7/10 covered), SLSA (tool=L0, target L2), MITRE ATT&CK (T1195/T1059/T1105/T1552/T1567/T1543/T1485/T1134 mapped), CWE (CWE-78/-94/-502/-22/-200 absent or single documented exception). Scored: Security 4/5, Robustness 4/5, Reliability 4/5, Maintainability 4/5. Headline: gaps are in OSS release integrity, not detection — P0-1 (signing) is highest leverage.

---
_End of session state. If anything here is unclear, ASK before acting — this is stake-sensitive._
