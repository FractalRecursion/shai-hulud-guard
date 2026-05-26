# Design notes — `shai_hulud_guard`

This is a deliberately-opinionated document. It is **not** a user guide
(`README.md` is). It is **not** a Claude Code instruction file (`CLAUDE.md`
is). It exists to make the *judgment calls* behind the code legible to a
reviewer who wants to know whether the design is coherent or accidental.

Three sections:
1. **Invariants** — load-bearing rules the code respects everywhere.
2. **Trade-offs** — non-obvious decisions, what they cost, what they buy.
3. **Non-goals** — things this tool deliberately does not do, with reasons.

---

## 1. Invariants

These are commitments the code keeps under all circumstances. They appear in
[CLAUDE.md §5][claude] for AI collaborators; this section explains them for
human reviewers.

[claude]: ../CLAUDE.md

### 1.1 Stdlib-only at runtime

No `requests`, no `colorama`, no `click`, no `rich`. A defensive supply-chain
tool that itself depends on five transitive packages is an obvious own-goal:
the very compromise vector we're defending against is `pip install <thing>`
pulling in unaudited downstream packages.

Cost: ~15 lines of `urllib.request` boilerplate per HTTP call instead of
`requests.get(url).json()`. Ansi colour codes are hand-rolled rather than
delegated to `colorama`. Worth it.

Carry forward: future maintainers must hold this line. `pyproject.toml` has
zero `dependencies`; all `dev`-group items (pytest, ruff, pyinstaller) are
build-time only.

### 1.2 Sentinel-bracketed reversibility

Every file `--protect` modifies in user-owned configuration (shell profile,
`.npmrc`, crontab) is wrapped between exact-string sentinel comments:

```
# === shai-hulud-guard (remove with: python shai_hulud_guard.py --unprotect) ===
... lines ...
# === /shai-hulud-guard ===
```

`--unprotect` strips **only** the bracketed blocks. The sentinel strings are
constants `_SHAI_START` and `_SHAI_END` in source. **These strings are
versioned-stable**: changing them would orphan blocks written by older
installs.

Why this matters: a security tool that can't be cleanly uninstalled is one
the user can't safely try. The first thing the cautious sysadmin wants to
know is "if I run this and it breaks something, can I revert?". The answer
here is one command.

### 1.3 Never execute target package code

Tarballs are read in-memory via `tarfile.open(fileobj=io.BytesIO(data))`.
Wheels are read in-memory via `zipfile.ZipFile(io.BytesIO(data))`. Members
are inspected via `extractfile()` / `zf.read()` and decoded as text. **At no
point** is the archive extracted to disk, `import`ed, `exec`ed, `eval`ed, or
passed to `node` / `bun` / `python -c`.

The whole point of `--check` is to inspect a package *before* installing it.
Executing the package to inspect it would defeat the purpose and risk
auto-detonating the payload we're trying to identify.

Even seemingly-safe refactors that introduce `tarfile.extractall()` with a
`members=` filter are forbidden — malicious tarballs with path-traversal
members can escape restricted extracts. In-memory `extractfile` cannot
escape because nothing is written to disk.

### 1.4 Never auto-rotate credentials

The worm's persistence daemon polls GitHub every 60 s. If it detects a token
revocation, it triggers `rm -rf ~/` (or the Windows equivalent). **Revocation
is the most dangerous action on an infected machine**, and it must happen
*after* the daemon has been removed.

`shai_hulud_guard` therefore never calls `gh auth logout`, `npm token revoke`,
`aws iam delete-access-key`, `gcloud auth revoke`, `az ad sp credential reset`,
or any equivalent. Even with `--auto`, credential rotation is presented as a
manual checklist that the operator runs *after* the daemon is confirmed
removed.

This is the most important invariant. Convenience features that violate it
have killed victims' data in real incidents. See [`run_incident()` §5.7][claude].

### 1.5 No outbound network calls outside npm/PyPI registries

The scanner makes outbound HTTPS calls **only** to:
- `https://registry.npmjs.org/<package>` and the `dist.tarball` URLs it returns.
- `https://pypi.org/pypi/<package>/json` and the release URLs it returns.

No telemetry, no crash reporting, no analytics, no auto-update check. The
`--diagnose` output is written to a local file; the user pastes it into an
LLM themselves. We don't transmit it.

A telemetry endpoint in a security tool is an attack target. Not having one
is the strongest defence.

### 1.6 Credentials are listed by presence, never by content

`CHECK 5` lists credential file paths that exist on disk. It calls
`Path.exists()` and reports paths and severity. **It never calls
`Path.read_text()` or `read_bytes()` on those files**, never logs their
contents to a report, never includes them in JSON output, never transmits
them anywhere.

This rule extends to every future feature: memory snapshots, "include
context for the LLM", auto-upload, telemetry. If a feature appears to need
credential contents, the feature is redesigned.

### 1.7 The 8-step incident-response ordering is load-bearing

```
STOP → ISOLATE → IMAGE → REMOVE DAEMON → ROTATE CREDS → AUDIT PUBLISH → REBUILD → REPORT
```

The ordering reflects real operational constraints:
- **STOP first** because revoking tokens before daemon removal triggers
  `rm -rf ~/` (§1.4).
- **ISOLATE before IMAGE** because the worm continues exfiltrating during
  imaging otherwise.
- **IMAGE before REMOVE** because forensic evidence is destroyed once the
  daemon's artefacts are deleted.

Do not collapse, reorder, or "tidy up" this sequence. Operators reading the
incident guide under pressure depend on the order being correct.

---

## 2. Trade-offs

### 2.1 Single canonical version vs. CLI + UI parallel scripts

**Decision:** one script — `shai_hulud_guard.py` — accessed via flags.

We considered keeping two versions (a small CLI for CI and a TUI for
operators), as the v1.1 + v2.0 archived branches did. We rejected this for
v2.4:

- Maintaining two scripts in sync triples the surface area for IOC drift.
- The TUI's audience is narrow — operators under stress, on a particular
  machine. The same audience is well-served by `--patch` + `--incident`
  printed output.
- A second script doubles the audit surface for a reviewer evaluating the
  project as a portfolio piece.

Both archived versions are preserved in `legacy/` for reference. The cost
is that operators who genuinely prefer a TUI must use `legacy/v2.0` and
accept it doesn't have the post-v2.0 features (PyPI, lockfile, protect,
self-test, etc.).

### 2.2 Exit codes only on `--check` / `--check-pypi`, not on `--scan`

**Decision:** `--check` / `--check-pypi` exit `1` when `risk_score ≥ 40`;
`--scan` always exits `0` unless an internal error occurs.

Reasoning:
- `--check` is a **pre-install gate** — its exit code is consumed by the
  wrapper scripts (`npm_safe.sh`, `pip_safe.ps1`) to block or allow installs.
  A non-zero exit there means *something useful for automation*.
- `--scan` is a **forensic discovery tool** — operators run it on machines
  they suspect are infected. Failing the process every time `--scan` finds
  *anything* would cause incident-response fatigue: scripts would suppress
  the exit code, then the operator stops trusting the exit code, then a real
  CRITICAL becomes invisible.
- The cost is asymmetric. False-positives in `--check` lose a developer ten
  minutes of investigation; false-positives in `--scan` can convince an
  operator to wipe a clean machine (CISA's "incident-response fatigue"
  finding).

If we add richer exit codes in v2.5, they will be additive — `0` always
remains "no critical findings".

### 2.3 Two-phase `--protect`

**Decision:** `--protect` always-on Phase 1 (inert file writes) + opt-in
Phase 2 (system modifications via `--setup-alias`, `--setup-npmrc`,
`--setup-cron`, `--install-hook`).

Phase 1 alone (which happens whenever `--protect` runs) writes wrapper
scripts and templates that **do nothing** until the operator explicitly
activates them. This is safe to run on any machine.

Phase 2 modifications touch the user's environment — shell profile, npm
config, cron, git hooks. Each is sentinel-wrapped (§1.2) and reversible.
Each requires an explicit flag (or an interactive Y prompt) before it
happens.

The cost is that Phase 1 alone doesn't *do* anything until the operator
activates the wrappers. The benefit is that operators can run `--protect`
exploratively without worrying about side effects.

### 2.4 Comment stripping before pattern matching

**Decision:** `_strip_comments(text, ext)` removes `//`, `/* */`, and `#`
comments before running `MALICIOUS_PATTERNS` on source files.

Without this, source files in legitimate packages produce dozens of false
positives:
- The `cryptography` Python library has documentation comments explaining
  `/etc/shadow` access semantics.
- numpy's `command/egg_info.py` has comment-line examples of shell injection
  patterns.
- Any security-relevant package mentions the patterns we're matching, in
  prose.

Cost: a payload that *hides* malicious patterns in comments evades the
scanner. Mitigation: comments don't *execute*, so a payload buried purely
in comments has no effect. A payload that executes string-form-of-comments
via `eval` would still trigger the eval-of-decoded-content pattern at
HIGH severity.

This is a deliberate calibration: optimise for the false-positive cost on
real packages over the false-negative cost on contrived payloads.

### 2.5 Non-executing-directory finding demotion

**Decision:** `_distrib_noise_filter()` treats **non-executing directories**
(`_NOEXEC_DIRS` — tests *and* CI pipelines: `/tests/`, `/__tests__/`, `/spec/`,
`/fixtures/`, `/.github/`, `/.circleci/`, `/.evergreen/`, `/.azure-pipelines/`,
`/.buildkite/`, `/.gitlab/`, `/.teamcity/`, `/ci/`, …) specially:
- **CRITICAL → MEDIUM** (visible at +4, but cannot hard-block a legit package),
- everything below CRITICAL → **LOW** (suppressed).

Soft-noise dirs (`/docs/`, `/examples/`, `/vendor/`, `/third_party/`) get the
milder one-level demotion and keep CRITICAL (vendored code *can* be imported).

Reasoning: files in tests and CI pipelines do not execute during `npm install`
/ `pip install`. The empirical driver was the calibration benchmark, which
flagged three legitimate top-50 packages as false "do-not-install" verdicts
purely on test/CI content:
- **Pillow** — `Tests/test_imagegrab.py` spawns PowerShell to grab the screen.
- **pymongo** — `.evergreen/scripts/resync-all-specs.py` (MongoDB's Evergreen
  CI) spawns shells.
- **virtualenv** — `tests/unit/` legitimately creates `.pth` files and spawns
  shells (that is literally what virtualenv does).

The first iteration demoted CRITICAL→HIGH, but two HIGH test-findings (+20 each)
still summed to a false 55/100 on virtualenv. CRITICAL→MEDIUM (+4) prevents
accumulation while keeping the finding visible.

Cost: a payload that smuggles itself into `tests/` and is later imported by a
script that *does* run would be downgraded. Mitigation: the script that imports
it — `setup.py` / a lifecycle hook — is a `_SETUP_FILE` scanned at FULL severity
(never demoted), so the real execution trigger is always caught. Test/CI files
are not exercised at install. Regression-guarded by `tests/test_noise_filter.py`.

### 2.6 Risk-score weights are inline constants, not configurable

**Decision:** the +40 / +25 / +10 / +5 weights for publish-age, the +20 for
maintainer drift, etc., live as literal constants in the code. They are not
configurable via CLI flags or environment variables.

Reasoning: tuning these is a **calibration** decision, not a user
preference. Exposing them as knobs would tempt operators to "ignore" warnings
by lowering thresholds, which is exactly the failure mode we're trying to
prevent. The benchmark suite (`benchmarks/run_calibration.py`) gives
maintainers the data they need to retune; users get the result, not the
dials.

Cost: an operator who is *certain* a finding is a false positive has no in-
tool way to silence it. Mitigation: `--check` is read-only; nothing breaks
if a high score is overridden with `SHAI_SKIP=1`. The operator's
override is logged in shell history, not in the tool's calibration.

### 2.7 Tarballs are downloaded in full before scanning, not streamed

**Decision:** `fetch_bytes()` downloads the entire tarball into memory before
`scan_tarball_bytes()` examines it.

Streaming would reduce memory for very large tarballs. We rejected it
because:
- Streaming would force `tarfile.open(mode="r|gz")` (the stream-friendly
  mode), which does not support random member access — you cannot revisit
  earlier members. This makes integrity verification (SHA-512) impossible
  in a single pass.
- A 2.3 MB tarball (Shai-Hulud's largest known payload) is fine in memory.
- Real npm packages cap out around 100 MB; PyPI sdists at 50 MB. Both
  comfortable on modern hardware.

The trade is more memory for *integrity-verifiable* tarball reads. Worth it.

### 2.8 GHSA `advisories` are populated from OSV, not hand-typed

**Decision:** `KNOWN_BAD` entries carry an `advisories` list of authoritative
GHSA IDs, populated (and kept current) by `tools/refresh_advisories.py` — a
**maintainer-only** helper that queries OSV.dev (Google's aggregator of GHSA +
NVD + the npm/PyPI malware feeds). It is **never** run by the scanner: §5.4
forbids the scanner from phoning home anywhere but the npm/PyPI registries, so
the network-touching refresh lives in a separate dev tool (same precedent as
`benchmarks/run_calibration.py`).

Reasoning: inventing a GHSA ID is *worse* than an empty field — it sends
consumers to non-existent advisories. So population is gated on a verifiable
source. The tool prints suggestions; a human verifies each at
`github.com/advisories` (§5.5); only then are they committed. Only the
**supply-chain / malicious-code** advisory matching the `bad` version is
recorded — unrelated CVEs in the same package (e.g. guardrails-ai's older
XXE / RCE CVEs) are deliberately excluded.

This process also surfaced and corrected a misattribution: the Wave-1 entry was
`tinycolor2` (an *uncompromised* package — 0 OSV vulns); the package actually hit
by the Sep-2025 worm is `@ctrl/tinycolor` (GHSA-qjqf-7j6f-82c4), matching the
cited StepSecurity "ctrl-tinycolor" post-mortem.

Cost: the mapping is only as fresh as the last maintainer run. Mitigation: the
tool exits non-zero when a tracked package has a new advisory not yet recorded,
so it can run as a periodic CI / cron check.

### 2.9 Subprocess analysis is split by intent (curl/wget vs. bare shell)

**Decision:** the single pattern that flagged any `subprocess.run(["sh" | "bash"
| "curl" …])` as HIGH was split into three, by *intent*:
- a network **downloader** (`curl`/`wget`) spawned from a package → **HIGH**;
- a shell carrying a **download / pipe-to-shell / remote `-c` / reverse-shell /
  encoded payload** → **HIGH** (the real download-pipe-execute TTP);
- a **bare local shell interpreter** (e.g. `["sh", "./autogen.sh"]`) → **MEDIUM**.

Reasoning: the empirical driver was matplotlib==3.8.3 scoring 45/100 — one MEDIUM
short of the do-not-install threshold. The HIGH came from `setupext.py` running
`subprocess.check_call(["sh", "./autogen.sh"])` — autotools generating the
FreeType build config. Every native-extension package does this (numpy, scipy,
lxml, Pillow shell out to configure/make). Running a *local build script* is not
the worm's behaviour; *download-pipe-execute* is. Splitting by intent drops the
legit native-build case to MEDIUM (+4, still visible) while keeping the actual
attack shape at HIGH. **matplotlib fell 45→25, numpy 37→21**, with no change to
the true-positive set (those hard-block via `KNOWN_BAD`, not this pattern).

Cost: a package that spawns a bare shell which *then* misbehaves in a way none of
the HIGH escalators catch would score only MEDIUM. Mitigation: the definitive
CRITICALs (home wipe, C2 domains, token literals, reverse shells, `/proc/pid/mem`,
`os.system` with a downloader) keep their own patterns, and the "silent file
download" (`curl -s http` / `wget -q http`) pattern is independent. Regression-
guarded by `tests/test_patterns.py` (build-shell = MEDIUM, payload-shell = HIGH,
curl = HIGH).

---

## 3. Non-goals

Things this tool deliberately does not do. Each is paired with the existing
tool that does it well, or the reason it shouldn't be done at all.

### 3.1 Not a runtime sandbox

We do not execute the package being inspected. We rely entirely on static
content. Tools that execute packages in a sandbox to observe behaviour
(Socket, Snyk Code, Wiz) are complementary, not substitutes. **Use both.**

If you're hitting a zero-day variant that evades static patterns, the
sandbox tools will likely catch it via behavioural deviation. If you're
hitting a known-bad version, this tool will catch it via `KNOWN_BAD` while
the sandbox is still spinning up.

### 3.2 Not a behavioural-analysis SaaS

We don't ingest network telemetry, system-call traces, eBPF events, or
runtime introspection. We don't have an opinion on whether your build
machine was reaching out to `evil.example.com` last Thursday at 3 AM. EDR
products (CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne)
do this and do it well.

### 3.3 Not a continuous monitor

`shai_hulud_guard` is a snapshot tool. `--scan` answers the question "is
this project infected *right now*?". It does not run in the background
watching for new IOCs.

`--protect --setup-cron` schedules `--scan` to run daily, which is the
weakest form of monitoring (24-hour latency). For real continuous monitoring,
integrate the `--json` output into your SIEM / log pipeline and run the
scanner from your existing scheduling infrastructure.

### 3.4 Not a credential vault / secret scanner

We do not look *inside* credential files. We list their presence. Tools that
scan file contents for credentials (TruffleHog, gitleaks, detect-secrets)
do this; they are complementary. Note that a credential scanner running on a
Shai-Hulud-infected machine could itself leak credentials to a poisoned IDE
extension — the threat model matters.

### 3.5 Not a CI/CD platform

We generate a `.github/workflows/shai_hulud_supply_chain.yml` template that
operators commit themselves. We don't run pipelines, store results, manage
secrets, or talk to webhook endpoints. The CI integration is the YAML file;
GitHub Actions runs it.

### 3.6 Not an installer / package manager

`npm_safe.sh` and `pip_safe.ps1` are **wrappers**, not replacements. They
delegate to the real `npm` / `pip` after the scan passes. We do not resolve
dependency graphs, manage lockfiles, build native modules, or run
postinstall hooks. The real package manager does all of that — we just
intercept the install-trigger point.

### 3.7 Not an LLM agent

`--diagnose` and `--json --llm_instructions` produce *artefacts* that pair
well with an LLM, but the scanner itself does not call any LLM API.
Reasoning: §1.5 (no outbound calls), §3.2 (no SaaS dependence), and the
practical observation that LLM costs and latencies don't fit inside a tool
that needs to be runnable in an air-gapped incident-response environment.

---

## Conclusion

This is a small tool. The smallest version that solves the problem is v1.1
(975 lines) — still in `legacy/`. v2.4 adds substantially more: PyPI,
lockfile audit, typosquatting, classification, patch script generation,
sentinel-based protection, JSON output, diagnosis reports, self-test.
Each addition pays for its lines of code by closing a documented attack
vector or unlocking a needed integration point.

The invariants in §1 are the things that *cannot* be traded for convenience.
The trade-offs in §2 are decisions that *were* traded, with the reasoning
recorded. The non-goals in §3 are the boundary — where this tool stops and
other tools start.

A reviewer assessing this project's coherence should find that the code in
`shai_hulud_guard.py` respects every invariant, makes every trade-off
deliberately, and stays inside every non-goal. If they don't, that is a
bug, not a feature; report it.
