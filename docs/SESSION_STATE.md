# SESSION STATE — shai_hulud_guard (handoff for context reset)

> Authoritative resume document. **Project root:** `C:\Users\Utente\Shai_Hulud_Guard\`.
> Do NOT touch `C:\Users\Utente\shai_hulud_guard.py` (an old v2.3 backup outside the repo).
> For the *verbatim* detection logic, risk weights, and safety invariants, **`CLAUDE.md` is
> authoritative** — this doc is the point-in-time "what changed / what's next" layer. If the two
> ever diverge, trust the code + `CLAUDE.md`.

---

## 0. CURRENT STATE & EXACT NEXT ACTION

- **Phase:** v2.4.0 is feature-complete, GitHub-productionised (CI/signing/release/security workflows),
  and the post-consolidation detection fixes are done & verified. **Everything is LOCAL — nothing pushed.**
- **Git:** branch **`main`** (also `release/v2.4.0`). Commits are **SSH-signed → "Verified"** from
  `5c742f9` onward (the first 3 historical commits stay unsigned by design). Tag **`v2.4.0`**
  (annotated, signed) — will be re-pointed to the latest commit before push.
- **gh CLI:** installed and **authenticated as `FractalRecursion`** (token scopes incl. `repo`,`workflow`).
- **Validation (last run, all green):** `pytest` **104 passed** · `ruff check .` **clean** ·
  `--self-test` **6/6** · calibration FP/TP healthy (see §4) · `--version` = 2.4.0.

**EXACT NEXT ACTION (user-gated):**
1. **Commit** the post-consolidation fixes (this session's work — see §3), re-point the signed `v2.4.0` tag.
   *(Pending the version decision below.)*
2. **Phase B — go public** (all runnable now; the only human step, `gh auth login`, is already done):
   - `gh ssh-key add C:\Users\Utente\.ssh\id_ed25519_shguard.pub --type signing --title "shai-hulud-guard signing"` → flips commits to **Verified** on GitHub.
   - `gh repo create shai-hulud-guard --public --source . --remote origin --push` (**name MUST be `shai-hulud-guard`** — README badge URLs hardcode `FractalRecursion/shai-hulud-guard`).
   - `git push origin v2.4.0` → triggers `release.yml` (build + checksums + provenance); push to `main` makes the **CI badge** go green.
   - Repo settings: description, topics (`supply-chain-security npm pypi malware-detection incident-response python`), branch protection on `main` (require CI, allow admin override), confirm Scorecard `publish_results`.
3. **Then build the prioritised feature: one-command removal (§5).**

**OPEN DECISION:** keep **v2.4.0** (one clean first public release — recommended) or bump to **v2.4.1**
(record today's calibration/scoring fixes as a distinct release). No version bump applied yet.

---

## 1. PROJECT IDENTITY

- **What:** `shai_hulud_guard.py` v2.4.0 — single-file, **stdlib-only**, cross-platform (Win/macOS/Linux),
  Python 3.8+ CLI that detects / removes / prevents the **Shai-Hulud npm+PyPI supply-chain worm** and
  adjacent attacks. **Runtime deps: ZERO** (hard invariant). License **GPL-3.0**.
- **Modes (argparse contract):** `--scan --check --check-pypi --lockcheck --patch --auto --verify
  --self-test --protect --unprotect --install-hook --setup-alias --setup-npmrc --setup-cron --diagnose
  --json --incident --version`. **Exit:** `0` clean; `1` when `--check`/`--check-pypi` risk ≥ 40.
- **Repo layout:** `shai_hulud_guard.py` (canonical) · `CLAUDE.md` (READ FIRST — authoritative) ·
  `README.md` `QUICKSTART.md` (now v2.4) `CHANGELOG.md` `CONTRIBUTING.md` `SECURITY.md` `CODE_OF_CONDUCT.md`
  `LICENSE` `BENCHMARKS.md` · `pyproject.toml` `build.py` `build.ps1` `Makefile` ·
  `tests/` (104 tests) · `docs/{DESIGN,THREAT_MODEL,JSON_SCHEMA,SECURITY_REVIEW,RUFF,SESSION_STATE}.md` ·
  `benchmarks/run_calibration.py` · **`tools/refresh_advisories.py`** (NEW) ·
  `.github/` (workflows + templates, NEW) · `legacy/` (archived, unmaintained).

---

## 2. INFRASTRUCTURE ADDED THIS SESSION (Phase A — committed in `5c742f9`/`3263040`)

| Area | File(s) | Note |
|---|---|---|
| **Commit signing** | repo-local git config + `~/.ssh/id_ed25519_shguard{,.pub}` + `~/.ssh/allowed_signers` | SSH (ed25519), passphrase-free (signing-only key). `gpg.format=ssh`, `commit.gpgsign`/`tag.gpgsign` true (local). |
| **CI** | `.github/workflows/ci.yml` | matrix `os:[ubuntu,macos,windows] × py:[3.8,3.10,3.12]`; `ruff`+`pytest`+`--self-test`; SHA-pinned actions; py3.8 excluded on macos-latest (arm64). |
| **Release** | `.github/workflows/release.yml` | on tag `v*`: per-OS PyInstaller build + `SHA256SUMS` + SLSA provenance → GitHub Release. |
| **Security scanning** | `.github/workflows/{codeql,scorecard}.yml` | CodeQL (python) + OpenSSF Scorecard (`publish_results`). |
| **Presence** | `.github/dependabot.yml`, `ISSUE_TEMPLATE/{bug,feature,ioc,config}`, `PULL_REQUEST_TEMPLATE.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CODEOWNERS` | recruiter-grade. |
| **Badges** | `README.md` | live CI / CodeQL / Scorecard / release badges. |

---

## 3. DETECTION & DOC FIXES THIS SESSION (UNCOMMITTED — to be committed next)

1. **Subprocess pattern split by intent** (`shai_hulud_guard.py` `MALICIOUS_PATTERNS`, ~line 196): the old
   single "downloader/shell" HIGH pattern → **three**: network downloader (curl/wget) = **HIGH**;
   shell + download/pipe/remote-`-c`/reverse-shell/encoded payload = **HIGH**; **bare** shell
   interpreter (`["sh","./autogen.sh"]`) = **MEDIUM**. Root cause of the matplotlib FP. Generalised —
   helps every native-ext build. Rationale: `docs/DESIGN.md §2.9`. Tests: `tests/test_patterns.py`
   (`test_bare_build_shell_is_medium_not_high`, `…_download_pipe_shell_is_high`, `…_curl_downloader_is_high`).
2. **`/tools/` added to `_NOISE_DIRS`** (~line 684): release/dev tooling shipped in sdists (matplotlib
   `tools/gh_api.py`) is soft-noise (HIGH→MEDIUM), not install-time.
3. **OPEN-2 fixed** (`run_check` STEP 2.5, ~line 2192): maintainer scoring now maps by exact level
   `{HIGH:20, MEDIUM:10, LOW:0}` — a *removed* maintainer (LOW) now adds **+0** (was +10), matching CLAUDE.md §3.
4. **`KNOWN_BAD` advisories populated** from OSV.dev (GHSA IDs) + `tinycolor2` → **`@ctrl/tinycolor`**
   correction (the actually-compromised package; the old name had 0 OSV vulns) + **bad versions
   `["4.1.1","4.1.2"]`** added (GHSA-qjqf-7j6f-82c4). New maintainer tool **`tools/refresh_advisories.py`**
   (OSV-sourced, stdlib-only, never run by the scanner — §5.4). See `docs/DESIGN.md §2.8`.
5. **`build.py` bug fixed** (referenced a non-existent `"shai_hulud_guard V2.0.py"`) → builds canonical
   `shai_hulud_guard.py`, prints SHA-256; `build.ps1` + `Makefile` updated (dead `--v1/--v2` removed).
6. **`QUICKSTART.md`** rewritten for the v2.4 flag-based CLI.
7. Docs synced: `CLAUDE.md` (§1 tree, §3 noise dirs, §4.3 advisories, §8.1 count 104, §8.4 to-do),
   `CHANGELOG.md`, `BENCHMARKS.md` (numpy 37→21, matplotlib 45→25 corrected; see its recalibration note),
   `README.md` (tinycolor row), `docs/DESIGN.md` (§2.8 rewrite, §2.9 new).

**Advisory map applied:** @tanstack/react-router `[GHSA-5q7g-gw3w-r3rh, GHSA-g7cv-rxg3-hmpx]` · @tanstack/router
`[GHSA-g7cv-rxg3-hmpx]` · intercom-client `[GHSA-54pg-9963-v8vg, GHSA-4594-wxqv-j3pm]` · guardrails-ai
`[GHSA-xmpw-2vmm-p4p6]` · mistralai `[GHSA-wx9m-wx4f-4cmg]` · @asyncapi/cli `[GHSA-w364-4jj5-wj22]` ·
@ctrl/tinycolor `[GHSA-qjqf-7j6f-82c4]`.

---

## 4. VERIFIED RESULTS (this session)

- **Tests:** `pytest` **104 passed** (101 + 3 subprocess-split guards). `ruff check .` clean. `--self-test` 6/6.
- **False positives (lower = better; all well under thresholds):** matplotlib **45→25**, numpy **37→21**,
  scipy 13, pillow 13, lxml 8; npm max `react`=10; react/lodash/django = 0. No TP regression.
- **True positives (must be 100/PACKAGES_ONLY/exit 1):** @tanstack/react-router@1.169.5 ✅ · @tanstack/router@1.169.5 ✅ ·
  intercom-client@7.0.4 ✅ · guardrails-ai==0.10.1 ✅ · mistralai==2.4.6 ✅ · **@ctrl/tinycolor@4.1.2 ✅ (new)**.
  Advisories surface in `--json` findings. Watchlist (bad:[]) packages flag at 15–44 (known-target warning):
  @ctrl/tinycolor@4.1.0=15, @asyncapi/cli=20, @tanstack/react-query=25, @bitwarden/cli=44.
- **Calibration env note:** the full `run_calibration.py` uses a **60 s per-package fetch timeout**; on a slow
  connection the largest PyPI sdists (numpy/scipy/matplotlib/pandas) can TIMEOUT. Their fixed scores are
  confirmed via direct `--check-pypi` (no timeout). Regenerate the canonical `BENCHMARKS.md` in CI (fast link).

---

## 5. ⭐ PRIORITISED FEATURE — one-command removal of infected packages (`--remove`)

**Goal:** after a scan finds infection, remove it safely in ONE command. *Removal logic largely already
exists* (`run_patch`/`generate_remediation`/`_write_cleanup_script`/`_write_daemon_script`/`run_incident`)
— `--remove` is a thin orchestrator that chains scan → classify → remediate → execute in the **load-bearing
safe order**.

**Implementation sketch (for the next session):**
- Add `--remove` flag in `main()` (~line 3682); add `run_remove(path)` near `run_patch` (~line 2584).
- Flow: `run_scan()` → `classify_infection()`; if clean, exit 0. If infected, execute **in this order**:
  1. **Remove the persistence daemon FIRST** (`_write_cleanup_script`/`_write_daemon_script` logic).
     *Load-bearing:* the daemon's kill switch does `rm -rf ~/` on credential revocation (§5.2 / §5.7).
  2. **Remove infected packages by deleting `node_modules/<pkg>` + editing `package.json`** (npm) and
     `pip uninstall -y <pkg>` (PyPI). **For npm, do NOT run `npm uninstall` without `--ignore-scripts`** —
     a malicious `preuninstall`/`postuninstall` hook would execute (§5.1). Safest: delete the dir directly.
  3. **Delete payload files** (`router_init.js`, `setup_bun.js`, `bun_environment.js`, `setup.mjs`).
  4. **NEVER auto-revoke/rotate credentials** (§5.2) — print the manual rotation checklist *after* removal.
  5. Print audit/rebuild/report guidance (the `--incident` tail).
- **Confirmation:** interactive per-item confirm by default; `--auto`/`--yes` to skip (document the risk).
  Reuse `_execute_cmds`/`_execute_ps` (already noqa-S602-documented) for execution.
- **Exit codes:** `0` removed/clean; `1` if removal failed or manual steps remain. Document in CLAUDE.md §2.
- **Tests (add `tests/test_remove.py`):** synthetic infected dir → `run_remove` → assert daemon file gone,
  payload files gone, package removed, **no credential-revocation call**, and the daemon-before-anything order.
- **Invariants to honour:** §5.1 (never execute target code — `--ignore-scripts` / direct delete),
  §5.2 (no auto-revoke; daemon first), §5.7 (8-step order), §5.8 (subprocess list-form, explicit timeouts).

**Roadmap after `--remove`:** `--scan-file <path>` (vet a downloaded artifact before opening — reuse
`scan_tarball_bytes`/`scan_wheel_bytes`/`scan_text`) · P1 fuzz harness + `tests/test_protect.py` · P2 SARIF
output → GitHub Security tab, reusable GitHub Action, SBOM ingestion · GPG signing (user learning goal).

---

## 6. ENVIRONMENT / SAFETY NOTES

- **Bash sandbox:** none configured (no `sandbox` key in project `.claude/settings.local.json` or global
  `~/.claude/settings.json`); on Windows the seatbelt/bubblewrap sandbox does not apply, so commands run
  unsandboxed. The `.claude/settings.local.json` allowlist auto-approves read-only + scanner commands.
  The scanner is safe to run unsandboxed (reads tarballs in memory, never executes — §5.1).
- **Safety invariants** (`CLAUDE.md §5`, do NOT regress): §5.1 never execute target code · §5.2 never
  auto-revoke/rotate creds (daemon kill-switch wipes `~/`) · §5.3 never read credential file contents ·
  §5.4 never phone home except npm/PyPI registries (the OSV tool is a separate *maintainer* script) ·
  §5.5 every IOC needs a cited source · §5.7 incident order is load-bearing · §5.8 no `shell=True`.
- **Auto-touch note:** an editor/linter hook touches files between reads (Edit/Write may report "modified
  since read"); just re-Read then edit/write.

---

## 7. OPEN ITEMS / MINOR

- Version decision (v2.4.0 vs v2.4.1) — see §0.
- `BENCHMARKS.md` canonical full regen should run on a fast link/CI (local run timed out on big sdists).
- `docs/SECURITY_REVIEW.md §8` P1/P2 roadmap (fuzz harness, SARIF, Action, SBOM) still open.
- Watchlist edge: a `bad:[]` package at a *yanked* pinned version scores 0 (no tarball to scan); resolved
  for @ctrl/tinycolor by adding its bad versions. Consider applying the watchlist `+15` even when a pinned
  version fails to resolve (low priority).

_End of session state. If anything is unclear, prefer `CLAUDE.md` + the code, and ASK before destructive actions._
