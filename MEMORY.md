# MEMORY — Shai-Hulud Guard (on-demand project memory)

> **Read on demand, not every session.** `CLAUDE.md` (root) is authoritative for safety invariants,
> behaviours, and the live TODO; this file holds **state, history, calibration numbers, and the
> `--remove` build guide**. If the two diverge, trust the code + `CLAUDE.md`.
> Merged from the former `docs/SESSION_STATE.md` + `docs/HANDOFF_REMOVE.md` (git history keeps the originals).
> **Project root:** `C:\Users\Utente\Shai_Hulud_Guard\`. Do NOT touch `C:\Users\Utente\shai_hulud_guard.py`
> (an old v2.3 backup *outside* the repo).

---

## 1. Current state & exact next action

- **Phase:** v2.4.0 **PUBLIC + released.** Repo **https://github.com/FractalRecursion/shai-hulud-guard** (public).
  `release/v2.4.0` merged `--no-ff` into `main`; `main` pushed; signed annotated tag `v2.4.0` → `e37210a`.
  Version **stayed v2.4.0** (single clean first release).
- **Branches:** `main` @ `f39022f` (level with origin); **`feature/remove` @ `665efcd` (pushed)** holds the
  `--remove` pre-reqs (Phase 0a+0b, §6.0).
- **Release `v2.4.0`** assets: `SHA256SUMS`, `shai_hulud_guard.py`, per-OS binaries (`-linux-x86_64`,
  `-macos-arm64`, `-windows-x86_64.exe`). `release.yml` succeeded.
- **CI/CD:** `ci.yml` **8-job matrix** = `os:[ubuntu,windows,macos-latest] × py:[3.8,3.10,3.12]` **minus the
  `macos-latest + 3.8` cell** (arm64 macos-latest has no 3.8; the Intel `macos-13` runner was dropped as
  scarce — chronic queueing). 3.8 covered on Ubuntu+Windows; macOS on 3.10/3.12. CodeQL ✅ · OpenSSF
  Scorecard ✅ · Dependabot active.
- **Commit signing VERIFIED:** SSH ed25519 key registered on GitHub as a *signing* key; signed commits show
  **Verified**. First 3 commits (`0be0733`/`cdd134a`/`f3e2c4c`) unsigned by design (rewriting them would break
  the hashes referenced across the docs); every commit from the productionisation commit onward is signed.
- **Secrets/PII audit CLEAN:** no keys/tokens/credential files tracked; `.claude/` untracked; SSH *private*
  key in `~/.ssh/` (outside repo); personal Gmail removed → GitHub-only contact (@FractalRecursion).
  Test token-exemplars are concatenation-split (no scanner self-trips).
- **gh CLI:** authed as `FractalRecursion`; pushes over **HTTPS**; the SSH key is **signing-only**.
- **Validation:** `pytest` **104** · `ruff` clean · `--self-test` **6/6** · calibration healthy (§5).

**EXACT NEXT ACTION:**
1. (Optional) confirm the latest `main` `ci.yml` run is green; optionally add branch protection on `main`
   (require CI, admin override) once a collaborator joins.
2. **⭐ Build `--remove` (v2.4.1).** Pre-reqs (a)+(b) **DONE & committed** (`665efcd`); see §6. Then bump
   `VERSION`→`2.4.1`, tag & push.

---

## 2. Project identity

Single-file, **stdlib-only**, cross-platform (Win/macOS/Linux), Python 3.8+ CLI that detects / removes /
prevents the **Shai-Hulud npm+PyPI supply-chain worm** and adjacent attacks. **Runtime deps: ZERO** (hard
invariant). License **GPL-3.0**. CLI contract, module map, repo tree, risk scoring → `CLAUDE.md §1–§4`.

---

## 3. Infrastructure history (committed)

**Phase A (`5c742f9`/`3263040`)** — productionisation. All GitHub Actions are **SHA-pinned** (dogfoods the
action-poisoning defence the tool detects; Dependabot bumps the pins).

| Area | File(s) | Note |
|---|---|---|
| Commit signing | repo-local git config + `~/.ssh/id_ed25519_shguard{,.pub}` + `~/.ssh/allowed_signers` | SSH ed25519, passphrase-free (signing-only). `gpg.format=ssh`, `commit`/`tag.gpgsign` true (local). |
| CI | `.github/workflows/ci.yml` | ruff + pytest + `--self-test`; 8 jobs (see §1). |
| Release | `.github/workflows/release.yml` | on tag `v*`: per-OS PyInstaller + `SHA256SUMS` + SLSA provenance → Release. |
| Security scanning | `.github/workflows/{codeql,scorecard}.yml` | CodeQL (python, `security-and-quality`) + OpenSSF Scorecard (`publish_results` → badge + SARIF). |
| Community presence | `dependabot.yml`, `ISSUE_TEMPLATE/{bug,feature,ioc,config}`, `PULL_REQUEST_TEMPLATE.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CODEOWNERS` | IOC template enforces the §4.7 cited-source rule; `config` routes vulns to private reporting; PR template mirrors the §5 invariants + calibration gate. |
| README badges | `README.md` | live CI / CodeQL / Scorecard / release (old hardcoded "self-test 6/6" badge removed). |

**Ruff config** (`pyproject.toml`, explainer `docs/RUFF.md`): groups `E F W I B UP S C4 SIM RET`; `S`
(bandit) on because security tool. Deliberate ignores `S603 S607 S310 S324 E501` + `S110 SIM105 SIM102`
(best-effort `try/except/pass` is architectural — a forensic scan must not crash on one unreadable file,
§5.8). `legacy/` excluded; `benchmarks/` per-file-ignore (`assert` + typing/f-string). **`ruff check .`
exits 0** — CI enforces.

**Build** (`build.py`): builds **only** the canonical `shai_hulud_guard.py` (the dead `--v1/--v2` split +
`"shai_hulud_guard V2.0.py"` path were removed); `build.ps1` + `Makefile` updated in lockstep; release
workflow consumes it.

**Test suite** (`tests/`, 104; `conftest.py` loads root `shai_hulud_guard.py` via importlib; `guard` fixture
+ in-memory tarball builders; optional `legacy_v1`/`legacy_v2` fixtures skip if pruned). What each file guards:
- `test_patterns.py` — `scan_text` exemplars (one per `MALICIOUS_PATTERNS` entry — a pattern without an
  exemplar fails `test_each_pattern_has_an_exemplar` by design), dedup, ASCII-only Unicode-escape (§5.6).
- `test_known_bad.py` — `KNOWN_BAD` shape (incl. `advisories` key), `HIGH_VALUE_TARGETS` superset,
  `DAEMON_PATHS["windows"]==[]` guard, `CREDENTIAL_FILES`.
- `test_tarball.py` — `scan_tarball_bytes` payload-filename / worm-string / ASCII-obfuscation detection +
  i18n non-detection + robustness (binary / non-gzip / empty). (Worm-string fixture puts the marker in CODE,
  not a `//` comment — v2.4 strips comments before matching.)
- `test_finding.py` — `Finding` dataclass (defaults, `__iter__` back-compat, `to_dict()` keys, independent
  mutable default) + `_wrap_finding`.
- `test_typosquatting.py` — `_levenshtein` distances + `check_typosquatting` HIGH/MEDIUM/None boundaries.
- `test_lockfile.py` — `_lockfile_packages` v1 (nested) / v2–v3 (`packages` dict) normalisation.
- `test_noise_filter.py` — `_distrib_noise_filter` per-path-class incl. the CRITICAL→MEDIUM non-exec-dir rule
  (Pillow/pymongo/virtualenv regression guard).
- `test_sentinel.py` — `_sentinel_wrap`/`_sentinel_strip` round-trip + multi-block + idempotence (`--unprotect` guard).
- `test_json_schema.py` — `--json` schema (top-level + Finding keys, exit-code mapping, advisory enrichment,
  tuple normalisation) without network.

**Git:** `.gitignore` (build/cache, venv, `dist/`/`build/`/`*.spec`, runtime reports
`shai_hulud_report_*.txt`/`shai_hulud_pin_actions.txt`/`npm_safe_install.py`, `.env*`, `.claude/`);
`.gitattributes` (LF source, CRLF `.bat`/`.ps1`, binary blobs marked binary).

---

## 4. Detection & doc fixes — committed in `0685aac`

1. **Subprocess pattern split by intent** (`MALICIOUS_PATTERNS`): network downloader (curl/wget) = **HIGH**;
   shell + download/pipe/remote-`-c`/reverse-shell/encoded = **HIGH**; **bare** shell interpreter
   (`["sh","./autogen.sh"]`) = **MEDIUM**. Fixed the matplotlib FP; generalises to native-ext builds.
   `docs/DESIGN.md §2.9`. Tests in `test_patterns.py`.
2. **`/tools/` added to `_NOISE_DIRS`** — release/dev tooling shipped in sdists is soft-noise (HIGH→MEDIUM).
3. **OPEN-2 fixed** (`run_check` STEP 2.5): maintainer scoring maps by level `{HIGH:20, MEDIUM:10, LOW:0}`;
   a *removed* maintainer (LOW) now adds **+0** (was +10), matching `CLAUDE.md §3`.
4. **`KNOWN_BAD` advisories** populated from OSV.dev (GHSA IDs) + `tinycolor2` → **`@ctrl/tinycolor`**
   correction + bad versions `["4.1.1","4.1.2"]` (GHSA-qjqf-7j6f-82c4). New maintainer tool
   `tools/refresh_advisories.py` (OSV-sourced, stdlib-only, **never run by the scanner** — §5.4).
   `docs/DESIGN.md §2.8`.
5. **`build.py` bug fixed** (dead `"shai_hulud_guard V2.0.py"`) → builds canonical script, prints SHA-256.
6. **`QUICKSTART.md`** rewritten for the v2.4 flag CLI.
7. Docs synced: `CLAUDE.md`, `CHANGELOG.md`, `BENCHMARKS.md` (numpy 37→21, matplotlib 45→25), `README.md`
   (tinycolor row), `docs/DESIGN.md` (§2.8 rewrite, §2.9 new).

**Advisory map:** @tanstack/react-router `[GHSA-5q7g-gw3w-r3rh, GHSA-g7cv-rxg3-hmpx]` · @tanstack/router
`[GHSA-g7cv-rxg3-hmpx]` · intercom-client `[GHSA-54pg-9963-v8vg, GHSA-4594-wxqv-j3pm]` · guardrails-ai
`[GHSA-xmpw-2vmm-p4p6]` · mistralai `[GHSA-wx9m-wx4f-4cmg]` · @asyncapi/cli `[GHSA-w364-4jj5-wj22]` ·
@ctrl/tinycolor `[GHSA-qjqf-7j6f-82c4]`.

---

## 5. Verified results / calibration

- **Tests:** `pytest` **104** (101 + 3 subprocess-split guards). `ruff` clean. `--self-test` 6/6.
- **False positives** (lower = better; all under threshold): matplotlib **45→25**, numpy **37→21**, scipy 13,
  pillow 13, lxml 8; npm max `react`=10; react/lodash/django = 0. No TP regression.
- **True positives** (100 / PACKAGES_ONLY / exit 1): @tanstack/react-router@1.169.5 · @tanstack/router@1.169.5 ·
  intercom-client@7.0.4 · guardrails-ai==0.10.1 · mistralai==2.4.6 · **@ctrl/tinycolor@4.1.2**. Advisories
  surface in `--json`. Watchlist (`bad:[]`) flags 15–44: @ctrl/tinycolor@4.1.0=15, @asyncapi/cli=20,
  @tanstack/react-query=25, @bitwarden/cli=44.
- **Calibration env note:** `run_calibration.py` uses a 60 s/pkg fetch timeout; the largest PyPI sdists
  (numpy/scipy/matplotlib/pandas) can TIMEOUT on a slow link — their fixed scores are confirmed via direct
  `--check-pypi`. Regenerate the canonical `BENCHMARKS.md` in CI (fast link). `BENCHMARKS.md` (root) is the
  top-50 npm + top-50 PyPI scoring, **pinned to stable versions** for reproducibility (no publish-age noise).

---

## 6. `--remove` build guide (v2.4.1) — merged design + handoff

> Authority order: code + `CLAUDE.md` (authoritative) > this section. Grep anchors, not line numbers
> (line numbers drift; function names don't). This guide does not paste code already in the repo.

### 6.0 Status — Phase 0a+0b DONE (committed `665efcd`, on `feature/remove`, pushed, green)
- **0a executor safety:** new `_run(argv, cwd, timeout)` — single-command, `shell=False`, injection-proof,
  never raises, tolerates non-zero exit. `_execute_cmds` now takes `List[List[str]]`; all 5
  `generate_remediation` call sites converted to argv (systemctl/launchctl daemon removal, `npm
  uninstall`/`cache clean`/`ci`). `npm uninstall` carries **`--ignore-scripts`** (auto-exec + printed advice,
  §5.1); `_write_cleanup_script` uses `shlex.quote`. `_execute_ps` left argv-form (only hardcoded constants
  interpolated into `-Command`). `import shlex` added; last `shell=True`/`noqa` removed.
- **0b detection:** F1 CRITICAL reversed-marker pattern (`niagA oG eW ereH|duluH-iahS`) with cited source +
  required exemplar in `tests/test_patterns.py::EXEMPLARS`.

### 6.1 Goal
After a scan finds infection, remove it in ONE command. Removal logic largely exists
(`run_patch`/`generate_remediation`/`_write_cleanup_script`/`_write_daemon_script`/`run_incident`) —
`--remove` is a thin orchestrator chaining scan → classify → remediate → execute in the **load-bearing safe order**.

### 6.2 LOCKED decisions (user-approved — do not relitigate)
- **Default posture:** **dry-run preview** (prints the plan, changes nothing); **`--apply`** to execute;
  `--apply --yes` fully non-interactive.
- **Ecosystem:** **npm-first**; PyPI a follow-up.
- **Destruction model:** **quarantine, never delete** — move artifacts into `.shai-hulud-quarantine/<UTC>/`
  with a `manifest.json` (orig path, action, reason). Recoverable on false positive (§5.9).
- **Order:** **daemon FIRST**, then packages, then payloads (§5.2 kill-switch, §5.7).
- **Credentials:** **never auto-revoke/rotate** (§5.2) — print the manual checklist.
- **Exit code:** **`0`** on success (clean / dry-run / removed) **with the manual-rotation disclaimer in the
  SAME final block**; **`1`** only if the removal op itself failed (couldn't stop daemon / write quarantine).

### 6.3 Integration map (grep anchors)
- **`run_remove(project_path: Path, apply: bool=False) -> int`** near `run_patch`.
- **Extract `_gather_findings(project_path)` from `run_scan`** so `run_scan` + `run_remove` share one
  detection pass (daemon_found, bad_packages, payload_files, lockfile_critical, pattern_hits) without
  re-printing.
- **Reuse:** `classify_infection`, `generate_remediation`, `_write_daemon_script`, `_write_cleanup_script`,
  the `run_incident` tail, and the new `_run`/`_execute_cmds(argv)`.
- **argparse:** add `--remove` + `--apply` (+ optional `--yes`) in `main()`; validate `--apply`/`--yes` only
  with `--remove`; document exit codes in `CLAUDE.md §2`.

### 6.4 `run_remove` flow
1. `_gather_findings()` → `classify_infection()`. If `CASE_CLEAN` → "nothing to remove", **exit 0**.
2. Ordered plan (each item = a quarantine-move):
   - **Step 1 daemon FIRST:** `stop`+`disable` (argv) then **move** the unit/plist/task export into
     quarantine (also preserves forensic evidence, §5.7).
   - **Step 2 packages (npm):** **move `node_modules/<pkg>/`** into quarantine; **back up `package.json` +
     lockfile** before surgically removing the dep key (parse → delete → write, preserve indent). Never `npm
     uninstall` without `--ignore-scripts`; prefer the direct move (§5.1).
   - **Step 3 payloads:** move `MALICIOUS_FILENAMES` hits
     (`router_init.js`/`setup_bun.js`/`bun_environment.js`/`setup.mjs`) into quarantine.
   - **Step 4 credentials:** print the manual rotation checklist (already in `generate_remediation`). Never auto-revoke.
   - **Step 5 guidance:** the audit/rebuild tail from `--incident`.
3. **Dry-run (no `--apply`):** print every action with absolute paths, then `DRY RUN — nothing changed.
   Re-run with --apply to execute.` → **exit 0**.
4. **`--apply`:** execute Steps 1→3 in order; print Steps 4–5 + the co-located disclaimer banner → **exit 0**
   on success, **1** on operation failure.

### 6.5 Tests — `tests/test_remove.py` (new)
Synthetic infected dir (monkeypatch daemon path; create `node_modules/<bad>/`, payload files, tampered
`package.json` + lockfile); mirror `conftest.py` `guard` + `test_tarball.py` style. Assert: dry-run mutates
nothing + exit 0; `--apply` neutralizes daemon **before** packages/payloads (recording shim for order);
artifacts **moved** to `.shai-hulud-quarantine/` (NOT deleted) + `manifest.json`; `package.json`/lockfile
backed up; dep key removed; **no credential-revocation call**; disclaimer printed; exit 0; failure path
(unwritable quarantine) → exit 1; **no `shell=True`** anywhere; npm argv includes `--ignore-scripts`; clean
dir → "nothing to remove", exit 0.

### 6.6 Invariants (honour — see `CLAUDE.md §5`)
§5.1 never execute target code (quarantine-move / `--ignore-scripts`) · §5.2 daemon-first, never auto-revoke ·
§5.3 never read cred contents · §5.7 8-step order load-bearing · §5.8 argv only, explicit `timeout=` · §5.9
highest-stakes → quarantine, not delete.

### 6.7 Validation gates
`ruff check .` clean · `pytest` 104 + new `test_remove.py` · `--self-test` 6/6 · `--remove --path <synthetic>`
dry-run exit 0 · `--remove --apply --path <synthetic>` quarantines, exit 0. Calibration unaffected (no
pattern change).

### 6.8 Docs + version to update WHEN `--remove` lands (same commit)
`VERSION`→`2.4.1` (grep `VERSION       =`) + `pyproject.toml`. `CLAUDE.md` §2 (CLI + exit codes), §1 tree
(+`test_remove.py`), §8.2 test count, TODO #1 → done. `CHANGELOG.md`, `README.md`, `QUICKSTART.md` (+`--remove`
entry; full overhaul = TODO #10). This file §1/§6; `docs/DESIGN.md` (quarantine + dry-run rationale).

---

## 7. Open items / deferred backlog

Open items also live in `CLAUDE.md §8.4` (the first-glance TODO). Detail:
- Version decision v2.4.0 vs 2.4.1 (→ 2.4.1 when `--remove` lands).
- `BENCHMARKS.md` canonical full regen on a fast link / CI (local run times out on big sdists).
- `docs/SECURITY_REVIEW.md §8` P1/P2: fuzz harness (`scan_text`/`scan_tarball_bytes`/`_lockfile_packages`),
  `tests/test_protect.py` round-trip, SARIF, reusable Action, SBOM.
- **Watchlist edge:** a `bad:[]` package at a *yanked* pinned version scores 0 (no tarball to scan);
  consider applying the watchlist `+15` even when a pinned version fails to resolve (low priority).
- **Roadmap after `--remove`** (bumblebee-derived F2–F5; PENDING-gated `--scan-repo`): externalize IOC data →
  versioned `threat_intel/*.json` w/ structured `_indicators` (F2+F3); `--exposure-catalog` exact-match
  consumer (F4); MCP-config + VS Code-extension scan (F5); `--scan-repo <url>` (in-memory tarball, host
  allowlist, §5.4 relax — ⚠ user GO/NO-GO); `--scan-file <path>`; QUICKSTART overhaul; cognitive-accessibility
  statement; GPG signing (learning goal).

---

## 8. Environment / safety notes

- **Bash sandbox:** none configured; on Windows the seatbelt/bubblewrap sandbox doesn't apply → commands run
  unsandboxed. The `.claude/settings.local.json` allowlist auto-approves read-only + scanner commands. The
  scanner is safe unsandboxed (reads tarballs in memory, never executes — §5.1).
- **Safety invariants** are authoritative in `CLAUDE.md §5`. Quick map: §5.1 never execute target code · §5.2
  never auto-revoke (daemon kill-switch wipes `~/`) · §5.3 never read cred contents · §5.4 phone home only
  npm/PyPI (the OSV tool is a separate *maintainer* script) · §5.5 IOC needs a cited source · §5.7 incident
  order load-bearing · §5.8 no `shell=True`.
- **Auto-touch:** an editor/linter hook may touch files between reads ("modified since read") — re-Read then edit.

---

## 9. Git / repo context

- Remote **FractalRecursion/shai-hulud-guard** (public). **Don't commit to `main` directly — branch first.**
  SSH signing configured (commits show Verified); pushes over HTTPS (`gh` as FractalRecursion).
- Open PRs #1–#3 are **Dependabot** (unrelated). Commit shape for `--remove`: **commit A = Phase 0a+0b DONE
  (`665efcd`)**; commit B = `--remove` + tests + docs + version bump → one `feature/remove` PR.
- **Push vs PR — terminology lock.** The term is **Pull Request (PR)** — **never** "push request." `git push`
  alone makes a branch publicly visible on GitHub (the repo is public); a **PR is a separate merge proposal,
  NOT required for visibility**. Pipeline: `add → commit (local) → push (branch → GitHub, now public) → open
  PR (merge proposal) → CI/review → merge`. `working-tree clean` is a **local** state (`git status` zero) and
  is **orthogonal** to whether a PR exists.
- **Bug-fix-on-branch convention.** A bug found on a pushed feature branch (with or without an open PR) is
  fixed on the **same branch** → commit → push. An existing PR auto-tracks the branch HEAD; **never open a
  new PR just to land a fix**. A PR is opened *because* the branch is ready, not as a precondition for working
  on it. Choose merge strategy consistently — `release/v2.4.0` used `--no-ff`; for `feature/remove` either
  `--no-ff` (matches convention, preserves topology) or **squash-merge** (one tidy commit per feature) is
  acceptable. Avoid messy intermediate commits on `main`.

---

## 10. Sources

`CLAUDE.md` (authoritative) · `docs/DESIGN.md` · `docs/THREAT_MODEL.md`. IOC sources: `CLAUDE.md §4.7`. The
Perplexity study that seeded F1–F5: `perplexityai/bumblebee` `threat_intel/{mini-shai-hulud,antv-mini-shai-hulud}.json`.
