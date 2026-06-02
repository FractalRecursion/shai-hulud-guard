# HANDOFF — building `--remove` (Shai-Hulud Guard)

> **Purpose.** Self-contained handoff so a fresh session can build the `--remove` feature
> **without re-reading the prior conversation**, staying under the user's ~40% context budget.
> **Authority order:** the code + `CLAUDE.md` (authoritative) > `docs/SESSION_STATE.md §5` > this doc.
> This doc deliberately **does not paste code already in the repo** — it points to it by name +
> a `grep` anchor (line numbers drift; function names don't).

---

## 0. How to use this doc

1. Read §1 (what's already done) so you don't redo it.
2. Read §2 (locked decisions) — these are user-approved; do **not** relitigate them.
3. Build using §3–§6. Validate with §7. Update docs/version with §8.
4. Everything in §9 is **out of scope for this session** (deferred backlog + budget rule).

---

## 1. DONE this session — Phase 0a + 0b (validated green)

> **Re-verified all-green on 2026-05-29** after an accidental dual-instance/crash incident
> (two Claude Code sessions ran on this codebase at once and the interface crashed). No damage:
> no stale `.git/index.lock`; working tree = the expected 5 files only (no stray writes or
> surprise commits from the second instance); diffs intact; `ruff` clean (rules out F811
> duplicate definitions); `pytest` **104 passed**; `--self-test` **6/6**; `_run` and
> `_execute_cmds` each defined exactly once; F1 pattern + exemplar present once each. **No corruption.**

**Validation:** `python -m ruff check .` → clean · `python -m pytest -q` → **104 passed** ·
`python shai_hulud_guard.py --self-test` → **6/6**. (Self-test's `schtasks`/`pip` 20 s timeouts are
the sandbox environment, not regressions — the run exits 0.)

**Phase 0a — executor safety fix (the mandatory `--remove` prerequisite).** Eliminated the only
`shell=True` in the tool (was the §5.8 violation + command-injection surface that the old
`--remove` sketch would have inherited). In `shai_hulud_guard.py`:
- **New `_run(argv, cwd=None, timeout=60)`** — single-command executor, `shell=False`, never raises,
  tolerates non-zero exit (replaces the old shell `2>/dev/null` / `|| true`). *(grep `def _run`)*
- **`_execute_cmds` now takes `List[List[str]]`** (argv vectors, not shell strings). *(grep `def _execute_cmds`)*
- All **5 call sites converted to argv** in `generate_remediation`: daemon removal (linux `systemctl…`,
  darwin `launchctl…`), and `npm uninstall` / `npm cache clean` / `npm ci`. *(grep `_execute_cmds([`)*
- **`npm uninstall` now carries `--ignore-scripts`** (both the auto-exec path and the printed/advice line) — §5.1.
- **`_write_cleanup_script`** quotes package names with `shlex.quote` and emits `npm uninstall --ignore-scripts`. *(grep `def _write_cleanup_script`)*
- **`_execute_ps`** left as-is (already argv-form, `powershell -Command <const>`); added a comment that
  **only hardcoded constants** may be interpolated into its `-Command` string. *(grep `def _execute_ps`)*
- `import shlex` added; the old `# noqa: S602` removed (S603/S607 are ignored project-wide per `pyproject.toml`).

**Phase 0b — F1 reversed-marker detection.** Added a CRITICAL pattern catching the worm's reversed
banner (`niagA oG eW ereH|duluH-iahS`) with a cited source comment, in `MALICIOUS_PATTERNS`.
*(grep `Reversed Shai-Hulud worm marker`)*. Required exemplar added to
`tests/test_patterns.py::EXEMPLARS` (else `test_each_pattern_has_an_exemplar` fails by design).

**Not changed:** `VERSION` is still `2.4.0` (bump to `2.4.1` happens when `--remove` lands, §8).
The repo working tree also has **uncommitted doc edits** (CLAUDE.md §8.4 TODO #1 + #10–15,
SESSION_STATE §5) from planning — nothing committed yet (user: "don't commit the plan").

---

## 2. `--remove` — LOCKED design decisions (user-approved, do not change)

| Decision | Value |
|---|---|
| **Default posture** | **Dry-run preview**: `--remove` prints the exact plan and changes nothing. |
| **Execute** | requires **`--apply`**. `--remove --apply` = the one-command path for advanced users; `--remove --apply --yes` = fully non-interactive. |
| **Ecosystem** | **npm-first**. PyPI is a *follow-up* (not this version). |
| **Destruction model** | **Quarantine, never delete.** Move artifacts into `.shai-hulud-quarantine/<UTC-timestamp>/` with a `manifest.json` (original path, action, reason). Recoverable on false positive (§5.9). |
| **Order** | **Daemon FIRST**, then packages, then payloads (§5.2 kill-switch, §5.7). |
| **Credentials** | **Never auto-revoke/rotate** (§5.2) — print the manual checklist. |
| **Exit code** | **`0` on success** (clean / dry-run / removed) **with the manual-rotation disclaimer printed in the SAME final block** (unmissable). **Non-zero (`1`) only if the removal operation itself failed** (couldn't stop daemon / couldn't write quarantine). Leave a code comment + hook noting this may gain a "clean-state assessment" once the Perplexity layer lands. |

---

## 3. Integration map (where new code goes — grep anchors, not line numbers)

- **`run_remove(project_path: Path, apply: bool = False) -> int`** — add near `run_patch` *(grep `def run_patch`)*.
- **Extract `_gather_findings(project_path) -> <result>`** from `run_scan` *(grep `def run_scan`)* so both
  `run_scan` and `run_remove` share one detection pass (daemon_found, bad_packages, payload_files,
  lockfile_critical, pattern_hits). `run_scan` currently prints + returns an `int`; refactor so the
  gathering is reusable without duplicating scan logic or re-printing.
- **Reuse (do not rewrite):** `classify_infection` *(grep `def classify_infection`)*,
  `generate_remediation`, `_write_daemon_script`, `_write_cleanup_script`, the `--incident` tail
  *(grep `def run_incident`)*, and the **new `_run`/`_execute_cmds(argv)`** executor from §1.
- **argparse:** add `--remove` + `--apply` (+ optional `--yes`) in `main()` *(grep `def main` / `add_argument`)*.
  Validate `--apply`/`--yes` are only meaningful with `--remove`. Document exit codes in CLAUDE.md §2.

---

## 4. `run_remove` flow

1. `_gather_findings()` → `classify_infection()`. If `CASE_CLEAN` → print "nothing to remove", **exit 0**.
2. Build an **ordered plan** (each item = a quarantine-move, never a delete):
   - **Step 1 — daemon FIRST:** `stop` + `disable` (argv via `_execute_cmds`/`_execute_ps`), then **move**
     the unit file / plist / task export into quarantine (also preserves forensic evidence, §5.7).
   - **Step 2 — packages (npm):** for each bad pkg → **move `node_modules/<pkg>/` into quarantine**;
     **back up `package.json` + lockfile into quarantine** *before* surgically removing the dep key
     (parse → delete → write back, preserve indent). **Never** `npm uninstall` without `--ignore-scripts`;
     prefer the direct move (§5.1).
   - **Step 3 — payloads:** move `router_init.js` / `setup_bun.js` / `bun_environment.js` / `setup.mjs`
     (from `MALICIOUS_FILENAMES`, grep it) found in the tree into quarantine.
   - **Step 4 — credentials:** print the manual rotation checklist (already in `generate_remediation`). **Never auto-revoke.**
   - **Step 5 — guidance:** the audit/rebuild tail from `--incident`.
3. **Dry-run (no `--apply`):** print every action with absolute paths, then
   `DRY RUN — nothing changed. Re-run with --apply to execute.` → **exit 0**.
4. **`--apply`:** execute Steps 1→3 in order; print Steps 4–5 + the co-located disclaimer banner
   (§2 exit-code rule) → **exit 0** on success, **1** on operation failure.

---

## 5. Tests — `tests/test_remove.py` (new)

Use a synthetic infected dir fixture (monkeypatch the daemon path; create `node_modules/<bad>/`,
payload files, a tampered `package.json` + lockfile). Mirror the style of `tests/conftest.py`
(`guard` fixture) and `tests/test_tarball.py`. Assert:
- **Dry-run mutates nothing** (all files still present) and exits 0.
- **`--apply`:** daemon neutralized **before** packages/payloads (assert order via a recording shim);
  artifacts **moved to `.shai-hulud-quarantine/`** (NOT deleted) + `manifest.json` written;
  `package.json`/lockfile backed up; dep key removed; **no credential-revocation call**; disclaimer printed; exit 0.
- **Failure path** (e.g. quarantine dir unwritable) → exit 1.
- **No `shell=True`** anywhere; any `npm` argv includes `--ignore-scripts`.
- A clean dir → "nothing to remove", exit 0.

---

## 6. Invariants to honor (see `CLAUDE.md §5` — do not re-derive)

§5.1 never execute target code (quarantine-move / `--ignore-scripts`) · §5.2 daemon-first, never
auto-revoke creds · §5.3 never read credential contents · §5.7 8-step order load-bearing · §5.8
argv only, no `shell=True`, explicit `timeout=` · §5.9 removal is highest-stakes → quarantine, not delete.

---

## 7. Validation gates (must pass before declaring done)

```
python -m ruff check .            # must stay clean
python -m pytest -q               # 104 existing + new test_remove.py
python shai_hulud_guard.py --self-test          # 6/6
python shai_hulud_guard.py --remove --path <synthetic-infected-dir>          # dry-run, exit 0
python shai_hulud_guard.py --remove --apply --path <synthetic-infected-dir>  # quarantines, exit 0
```
Calibration suite (`benchmarks/run_calibration.py`) is unaffected by `--remove` (no pattern change in Phase 1).

---

## 8. Docs + version to update WHEN `--remove` lands (same commit)

- `VERSION` → **`2.4.1`** (grep `VERSION       =`) + `pyproject.toml` version.
- `CLAUDE.md`: §2 (CLI surface + exit codes), §1 tree (+`tests/test_remove.py`, +`HANDOFF_REMOVE.md`),
  §8.1 test count, §8.4 TODO #1 → ✅ done.
- `CHANGELOG.md`, `README.md`, **`QUICKSTART.md`** (add a `--remove` entry; full accessibility-first
  overhaul is the separate TODO #14).
- `docs/SESSION_STATE.md` §0 (next action) + §5; `docs/DESIGN.md` (quarantine + dry-run rationale).

---

## 9. Deferred backlog (NOT this session) + context-budget rule

Tracked in `CLAUDE.md §8.4`:
- **#10–11 Perplexity layer (F2+F3 externalized `threat_intel/*.json` + `_indicators`; F4
  `--exposure-catalog` exact-match consumer).** **Gated:** include only if doing all changes stays
  **< 40% context (pessimistic)**; the remove tool alone is estimated to cross 40%, so **defer to TODO**.
  Note for the user's question: the Perplexity exact-match method confirms *catalogued exposure* with
  certainty but is **not** a complete infection oracle (coverage gaps + exposure≠infection) — keep it
  framed as a low-FP *exposure* layer that complements daemon/heuristic detection.
- **#12** MCP-config + VS Code-extension scan.
- **#13 `--scan-repo <url>`** — **design LOCKED to in-memory tarball** (fetch source archive from
  `codeload.github.com`/GitLab, scan in RAM, never clone/extract/execute; add an explicit host
  allowlist to `fetch_bytes`; relax §5.4). Stays single-file (no new module). Build after `--remove`.
- **#14** accessibility-first QUICKSTART overhaul (command×function table; per-use-case time-ordered
  table; plain-text install + snippets).
- **#15** user-authored cognitive-accessibility statement of intent (neurodivergence / new-learner openness).

**Cadence the user asked for:** after completing each task, recap + report the actual context %; pause
near ~75% to let the user checkpoint.

---

## 10. Git / repo context

- Remote: **`FractalRecursion/shai-hulud-guard`** (public). On branch `main`, level with origin.
- **Do not commit to `main` directly** — branch first (e.g. `feature/remove`). SSH **signing** is
  configured (commits show Verified); pushes are over HTTPS (`gh` authed as `FractalRecursion`).
- Open PRs #1–#3 are **Dependabot** (unrelated). No PR exists for this work.
- Suggested commit shape: commit A = Phase 0a+0b (this session's code) [+ doc TODO edits]; commit B =
  `--remove` + tests + docs + version bump → one `feature/remove` PR.

---

## 11. Authoritative sources

`CLAUDE.md` (root, authoritative) · `docs/SESSION_STATE.md §5` · `docs/DESIGN.md` · `docs/THREAT_MODEL.md`.
IOC sources: `CLAUDE.md §4.7`. The Perplexity study that seeded F1–F5: `perplexityai/bumblebee`
`threat_intel/{mini-shai-hulud,antv-mini-shai-hulud}.json`.
