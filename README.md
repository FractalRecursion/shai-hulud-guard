# shai_hulud_guard

> **Current version: v2.4.0** — single-file Python CLI scanner, hardener, and proactive-defence tool for the Shai-Hulud npm / PyPI supply-chain worm family.
> Zero runtime dependencies. Python 3.8+. Linux / macOS / Windows.

<!-- Live status badges (turn green once the repo is pushed and Actions run). -->
[![CI](https://github.com/FractalRecursion/shai-hulud-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/FractalRecursion/shai-hulud-guard/actions/workflows/ci.yml) [![CodeQL](https://github.com/FractalRecursion/shai-hulud-guard/actions/workflows/codeql.yml/badge.svg)](https://github.com/FractalRecursion/shai-hulud-guard/actions/workflows/codeql.yml) [![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/FractalRecursion/shai-hulud-guard/badge)](https://securityscorecards.dev/viewer/?uri=github.com/FractalRecursion/shai-hulud-guard) [![Latest release](https://img.shields.io/github/v/release/FractalRecursion/shai-hulud-guard?sort=semver&display_name=tag)](https://github.com/FractalRecursion/shai-hulud-guard/releases/latest)

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE) [![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/) [![Runtime deps: 0](https://img.shields.io/badge/runtime%20deps-0-brightgreen)](pyproject.toml) [![Tests](https://img.shields.io/badge/tests-101%20passing-brightgreen)](tests/)

---

## TL;DR

```bash
python shai_hulud_guard.py --check <package>        # pre-install npm risk check
python shai_hulud_guard.py --check-pypi <package>   # pre-install PyPI risk check
python shai_hulud_guard.py --scan --path .          # scan an existing project
python shai_hulud_guard.py --patch --path .         # generate per-case remediation scripts
python shai_hulud_guard.py --protect --path .       # install proactive defences (reversible)
python shai_hulud_guard.py --unprotect --path .     # remove everything --protect installed
python shai_hulud_guard.py --self-test              # 6 assertions, synthetic infection roundtrip
python shai_hulud_guard.py --json --scan --path .   # machine-readable output for CI / LLM
```

Detailed docs:
- **[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)** — Wave 1-5 attack chain mapped row-by-row to defensive features.
- **[docs/DESIGN.md](docs/DESIGN.md)** — Invariants, trade-offs, non-goals.
- **[docs/JSON_SCHEMA.md](docs/JSON_SCHEMA.md)** — `--json` output schema with LLM-paste-ready example.
- **[BENCHMARKS.md](BENCHMARKS.md)** — False-positive / true-positive rates on live registry top-50.
- **[CHANGELOG.md](CHANGELOG.md)** — Full version history (v1.1 → v2.4).
- **[SECURITY.md](SECURITY.md)** — Disclosure policy.

---

## What it does

`shai_hulud_guard` detects, removes, and helps prevent the **Shai-Hulud npm/PyPI supply-chain worm** — a self-replicating worm family that has attacked the npm and PyPI ecosystems across five documented waves (September 2025 → present), attributed to threat actor **TeamPCP** (DeadCatx3, PCPcat, ShellForce, CipherForce).

The tool covers the full lifecycle:

```
   PREVENT          DETECT             RESPOND          HARDEN
   ───────          ──────             ───────          ──────
   --check     →    --scan       →    --patch     →    --protect
   --check-pypi     --lockcheck       --verify         --unprotect
                    --self-test       --diagnose
```

Each stage is a separate flag — there is no hidden state, no background daemon, no interactive prompts (unless you ask for them via `--protect`). The tool is fully scriptable and CI-friendly.

---

## Threat background

### Attack timeline

| Wave | Date | Entry vector | Scale |
|---|---|---|---|
| Wave 1 | September 2025 | Compromised maintainer credentials | 500+ packages |
| Wave 2 | November 2025 | CI/CD pipeline injection | 796 packages, 1,092 versions |
| Wave 3 | March 2026 | Aqua Security Trivy packages | Targeted |
| Wave 4 | April 2026 | SAP npm packages; Bitwarden CLI | Targeted |
| Wave 5 (Mini) | May 2026 | GitHub Actions cache poisoning + OIDC extraction | 172 packages, 403 versions, 518M cumulative downloads |

Wave 5 introduced **valid SLSA Build Level 3 provenance attestations on malicious packages** — bypassing all standard verification tools. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the row-by-row chain.

### Attack chain (one-paragraph summary)

Fork → poison Actions cache via `pull_request_target` → legitimate workflow restores poisoned cache → OIDC token extracted from CI runner memory → `preinstall` hook installs Bun silently → `router_init.js` (~2.3 MB obfuscated) sweeps **npm tokens, GitHub PATs, AWS/GCP/Azure keys, SSH keys, `.gitconfig`, `.npmrc`** → exfiltrates via three parallel channels (`git-tanstack[.]com`, Session network, GitHub API dead drops) → uses stolen npm token to publish infected versions of up to 100 of the victim's packages → self-propagates → installs `gh-token-monitor` daemon that polls GitHub every 60 s and triggers `rm -rf ~/` if any token is revoked.

That last step is why **revoking tokens before removing the daemon is catastrophic**. Both `--patch` and `--incident` enforce the correct ordering.

### Why standard defences failed (Wave 5)

| Defence | Failure mode |
|---|---|
| SLSA BL3 provenance | Injected before provenance generated — attestation was valid |
| 2FA on maintainer accounts | OIDC token extracted from CI runner memory, not from the account |
| `npm audit` | Designed for CVEs, not malicious code injection |
| `--ignore-scripts` on parent | Git / file transitive deps still run `prepare` hooks |
| Trusting well-known packages | TanStack, Mistral AI, UiPath, OpenSearch all compromised |

---

## Installation

No installation required. Single file, stdlib-only runtime.

```bash
# Clone
git clone https://github.com/USER/shai-hulud-guard.git
cd shai-hulud-guard

# Verify integrity
python shai_hulud_guard.py --version           # → shai_hulud_guard 2.4.0
python shai_hulud_guard.py --self-test         # → 6/6 PASSED
```

Optional — build a single-file binary via PyInstaller:

```bash
pip install -e ".[dev]"
python build.py                                # → dist/shai_hulud_guard[.exe]
```

The canonical artefact is the `.py` file. The PyInstaller binary is convenience for users who don't have Python installed.

---

## Usage

Every mode is invoked through a flag on `shai_hulud_guard.py`. No interactive menu, no hidden state. See `python shai_hulud_guard.py --help` for the live argparse output.

### Pre-install protection — before you `npm install` or `pip install`

```bash
# npm
python shai_hulud_guard.py --check lodash                          # latest
python shai_hulud_guard.py --check @tanstack/react-router@1.169.5  # specific version

# PyPI
python shai_hulud_guard.py --check-pypi numpy
python shai_hulud_guard.py --check-pypi requests==2.31.0
```

Returns a risk score 0–100. **Exit code 1 when score ≥ 40** — the wrapper scripts generated by `--protect` use this to block installs.

### Detect existing infection

```bash
python shai_hulud_guard.py --scan --path .         # 8 checks
python shai_hulud_guard.py --lockcheck --path .    # deep lockfile audit
```

### Respond to a confirmed infection

```bash
python shai_hulud_guard.py --patch --path .        # classify + generate remediation scripts
python shai_hulud_guard.py --patch --path . --auto # also auto-run non-destructive steps
python shai_hulud_guard.py --verify --path .       # re-scan after patch
python shai_hulud_guard.py --incident              # printed 8-step recovery guide
```

### Harden against the next attack

```bash
python shai_hulud_guard.py --protect --path .                                # Phase 1 only (write inert files)
python shai_hulud_guard.py --protect --path . --setup-alias --setup-npmrc --setup-cron  # also Phase 2 (modify system)
python shai_hulud_guard.py --unprotect --path .                              # full reversal
```

Every Phase 2 modification is wrapped in sentinel comments (`# === shai-hulud-guard … # === /shai-hulud-guard ===`) — `--unprotect` removes only those blocks, never touching pre-existing user content.

### Machine-readable output

```bash
python shai_hulud_guard.py --json --scan --path .
python shai_hulud_guard.py --json --check intercom-client@7.0.4
```

Single JSON object on stdout, no banner, no ANSI. Schema in [docs/JSON_SCHEMA.md](docs/JSON_SCHEMA.md). Designed to be:
- piped into `jq` for CI assertions,
- consumed by downstream tools without parsing human text,
- pasted into a frontier LLM for forensic suggestions when you don't recognise a finding.

---

## The 10 modes — what each one does

### `--scan` — existing-project audit (8 checks)

| # | Check | What it looks for |
|---|---|---|
| 1 | Persistence daemon | `gh-token-monitor` at documented Linux/macOS paths; Windows: queries Task Scheduler + Startup folder by known daemon names |
| 2 | `package.json` audit | Known-bad versions, high-value-target packages, non-registry deps (`git:`, `github:`, `file:`) which run `prepare` hooks unconditionally |
| 3 | Lock file + `.npmrc` hygiene | Missing lock file, npm config issues |
| 3.5 | Lock file deep analysis | Non-registry `resolved` URLs, missing `integrity` hashes |
| 4 | `node_modules` deep scan | Known payload filenames + 60+ IOC patterns against every lifecycle script (`preinstall`, `install`, `postinstall`, `prepare`) |
| 5 | Credential file inventory | Lists presence only — **never reads contents** |
| 6 | GitHub Actions workflows | `pull_request_target` + cache (Wave 5 vector), `id-token: write` at workflow level, tag-pinned actions |
| 7 | npm registry config | Detects non-default registries (potential C2 redirect) |
| 8 | Installed PyPI packages | Cross-references `pip list` against `KNOWN_BAD` PyPI entries |

### `--check` / `--check-pypi` — pre-install risk analysis (5 steps + 2.5 heuristics)

```
STEP 1  Registry metadata               (publish age, maintainers, version count)
STEP 2  Known compromised version DB    (hard-block if confirmed bad)
STEP 2.5 Dynamic heuristics             (maintainer drift, semver gap, new deps, typosquatting)
STEP 3  Lifecycle scripts               (registry metadata, no execution)
STEP 4  Dependency source validation    (flag git: / file: / http: deps)
STEP 5  Tarball download + integrity    (SHA-512 verify, in-memory pattern scan)
```

PyPI mode (`--check-pypi`) adds `.whl` wheel scanning (zip format) and SHA-256 integrity. Comment stripping (`_strip_comments`) runs before pattern matching on source files, dramatically reducing false positives on legitimate packages (numpy: 9/100, cryptography: 0/100, react: 0/100).

### `--lockcheck` — dedicated lockfile audit

Normalises `package-lock.json` v1 (nested `dependencies`) and v2/v3 (`packages` dict). Flags:
- Non-registry `resolved` URLs.
- Missing `integrity` hashes.
- Lifecycle scripts embedded inside lockfile entries.
- Known-bad versions resolved into the lock.

### `--patch` — infection classifier + remediation script generation

Classifies the infection state, then writes platform-specific remediation scripts:

| Case | Trigger | Script generated |
|---|---|---|
| `CLEAN` | No indicators | None — nothing to do |
| `UNCERTAIN` | Few low-confidence signals | None — manual review |
| `LOW_CONFIDENCE` | 3+ pattern hits, no daemon | None — investigate first |
| `DAEMON_ONLY` | Persistence found, no bad packages | `remove_daemon.{sh,ps1}` |
| `PACKAGES_ONLY` | Bad packages, no daemon | `clean_packages.{sh,ps1}` |
| `FULL_COMPROMISE` | Both | Both scripts (daemon FIRST — never rotate tokens before daemon is removed) |
| `LOCKFILE_TAMPERED` | Critical lockfile issues | `clean_packages.{sh,ps1}` |

With `--auto`, runs the non-destructive steps automatically. **Token rotation is never automated** — see `docs/DESIGN.md § safety invariants`.

### `--verify` — post-patch re-scan

Re-runs `--scan` after `--patch`. Used by the generated remediation scripts as their final step.

### `--self-test` — synthetic infection roundtrip

Creates synthetic infection artefacts in a `tempfile.TemporaryDirectory()`, runs the scanner, asserts 6 detection invariants, cleans up. Sandboxed; never executes any code. Used by CI to detect regressions in the scanner itself.

### `--diagnose` — forensic report for incident handoff *(Phase 3 — coming)*

Re-runs `--scan` and writes `shai_hulud_report_<UTC>.txt` containing system info (OS, Python, CPU, hostname, user, CI environment, shell, timestamp — never credential values), the findings list, and an LLM-ready summary. Paste into Claude / GPT-4 / Gemini for analyst-grade incident guidance.

### `--protect` / `--unprotect` — proactive defence (Phase 1 + Phase 2)

**Phase 1 — always-safe file writes:**
- `npm_safe.sh` / `npm_safe.ps1` — wrapper scripts that run `--check` before every `npm install`
- `pip_safe.sh` / `pip_safe.ps1` — same for `pip install`
- `.github/workflows/shai_hulud_supply_chain.yml` — SHA-pinned CI workflow template
- `shai_hulud_pre_commit.hook` — pre-commit hook template

**Phase 2 — opt-in system modifications (interactive or via flags):**
- `--setup-alias` — shell alias for `npm` and `pip` in your profile
- `--setup-npmrc` — `save-exact=true` in project `.npmrc`
- `--setup-cron` — daily scan via cron (Linux/macOS) or Task Scheduler (Windows)
- `--install-hook` — install pre-commit hook into `.git/hooks/`

Every Phase 2 modification is sentinel-wrapped. `--unprotect` removes only the bracketed blocks, leaving pre-existing user content untouched. Verified by `--self-test` and by `tests/test_sentinel.py`.

### `--incident` — printed 8-step recovery guide

```
STEP 1 — STOP:    Do NOT revoke tokens yet (daemon triggers rm -rf ~/)
STEP 2 — ISOLATE: Disconnect from network
STEP 3 — IMAGE:   Forensic snapshot before cleanup
STEP 4 — REMOVE:  Delete daemon (manually or via --patch generated scripts)
STEP 5 — ROTATE:  NOW revoke: GitHub, npm, AWS/GCP/Azure, SSH
STEP 6 — AUDIT:   Check npm publish history for unauthorised releases
STEP 7 — REBUILD: Wipe OS, rebuild from clean image
STEP 8 — REPORT:  npm security@npmjs.com | CISA cisa.gov/reporting
```

**The ordering is load-bearing — see `docs/DESIGN.md`.**

---

## IOC signature coverage

### Payload filenames (definitive indicators)

| Filename | Waves |
|---|---|
| `router_init.js` | All waves — core payload (~2.3 MB) |
| `setup_bun.js` | Waves 2–5 — Bun installer stub |
| `bun_environment.js` | Wave 2 |
| `setup.mjs` | Wave 1 — ESM variant |

### Pattern categories (60+ entries across 4 risk levels)

| Category | Risk | Examples |
|---|---|---|
| Worm identity | CRITICAL | `Shai-Hulud`, `TeamPCP`, `gh-token-monitor` campaign tags |
| Destructive payload | CRITICAL | `rm -rf ~/`, `rm -rf $HOME`, Windows home-wipe |
| C2 infrastructure | CRITICAL | `git-tanstack.com`, `webhook.site/<uuid>` |
| Token literals | CRITICAL | `ghp_<36>`, `gho_<36>`, `npm_<36>` |
| CI memory extraction | CRITICAL | `/proc/<pid>/mem`, OIDC env vars in HTTP context |
| Persistence | CRITICAL | LaunchAgent paths, systemd user service paths |
| Cloud credentials | HIGH | GCP ADC path, `AWS_SECRET_ACCESS_KEY` in HTTP context, Azure secrets |
| Bun injection | HIGH | `bun.sh/install` in lifecycle scripts |
| GitHub API abuse | HIGH | `api.github.com/user/repos` in scripts |
| Obfuscation | HIGH | `eval(atob(...))`, base64 literals ≥ 40 chars, ASCII chars as `\u00XX` escapes |
| Typosquatting | HIGH/MED | Levenshtein ≤ 2 from top-80 npm packages |
| CI/CD misconfiguration | LOW | `pull_request_target` flagged only in CHECK 6 context (with cache) |

### Known-compromised packages (current as of v2.4)

| Package | Confirmed bad version(s) | Waves |
|---|---|---|
| `@tanstack/react-router` | `1.169.5` | Wave 5 — May 2026 |
| `@tanstack/router` | `1.169.5` | Wave 5 — May 2026 |
| `@tanstack/react-query` | (scrutiny flag) | Wave 5 — May 2026 |
| `@mistralai/mistralai` | (scrutiny flag) | Wave 5 — May 2026 |
| `@uipath/apollo-core` | (scrutiny flag) | Wave 5 — May 2026 |
| `guardrails-ai` (PyPI) | `0.10.1` | Wave 5 — May 2026 |
| `mistralai` (PyPI) | `2.4.6` | Wave 5 — May 2026 |
| `intercom-client` | `7.0.4` | Wave 5 — May 2026 |
| `@bitwarden/cli` | (scrutiny flag) | Wave 4 — April 2026 |
| `tinycolor2` | (scrutiny flag) | Wave 1 — September 2025 |
| `@asyncapi/cli` | (scrutiny flag) | Wave 2 — November 2025 |

Authoritative sources (in priority order): GitHub Advisory Database → NIST NVD → OSV → Datadog IOC repo. See `CLAUDE.md § 4.7`.

---

## Calibration baseline

Every pattern change must preserve these scores. Run `python benchmarks/run_calibration.py` to verify against the live registry.

| Package | Expected score | Notes |
|---|:-:|---|
| `lodash` | 0/100 | clean |
| `react` | 0/100 | clean |
| `django` (PyPI) | 0/100 | clean |
| `flask` (PyPI) | 0/100 | clean |
| `cryptography` (PyPI) | 0/100 | clean — legitimate SSH/crypto code |
| `numpy` (PyPI) | ≤ 25/100 | one MEDIUM in `numpy/distutils/command/egg_info.py` (legitimate `cmdclass={}`) |
| `boto3` (PyPI) | ≤ 40/100 | clean code; the elevated score comes from fresh-publish-window (boto3 publishes multiple times/week) |
| `@tanstack/react-router` | ≤ 20/100 | known target warning + scrutiny flag |
| `intercom-client@7.0.4` | **CONFIRMED MALICIOUS** | hard-block at risk = 100 |

---

## Safe install workflow (when `--check` returns moderate risk)

```bash
# 1 — Install without executing lifecycle scripts
npm install <package>@<version> --ignore-scripts

# 2 — Inspect declared scripts
cat node_modules/<pkg>/package.json | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print(json.dumps(d.get('scripts',{}),indent=2))"

# 3 — Search for payload filenames
find node_modules/<pkg> -name "router_init.js" -o -name "setup_bun.js" -o -name "bun_environment.js"

# 4 — Re-enable postinstall only after manual review
# npm rebuild <pkg>@<version>
```

---

## Honest limitations

Five gaps — none softened. See `docs/DESIGN.md § limitations` for the full discussion.

1. **Pattern evasion** — each Shai-Hulud wave introduced new obfuscation. Zero-day variants produce zero pattern findings. This is not a theoretical concern; it has happened.
2. **Runtime-fetched payloads** — packages that download and execute code at runtime after install are not caught by the tarball scan. The lifecycle-script engine partially mitigates by flagging outbound fetch patterns, but a clean tarball that calls `curl` post-install is not stopped at scan time.
3. **Known-bad list latency** — active attack windows (2–8 h) precede public disclosure. During this window the tool detects anomalies (publish age, tarball size, suspicious patterns, maintainer drift) but cannot confirm compromise from the database.
4. **Provenance bypass** — Wave 5 confirmed that valid SLSA BL3 attestations don't indicate clean code when the build pipeline itself is compromised. This tool does not verify provenance and would not have been more useful if it did.
5. **`--ignore-scripts` bypass** — git/file-sourced transitive dependencies run `prepare` hooks unconditionally. The scanner flags these in CHECK 2 and pre-install STEP 4, but the root mitigation requires auditing the full dependency tree.

A non-zero risk score is a strong signal to investigate. **A zero risk score is not a guarantee of safety.**

---

## Contributing

IOC updates and confirmed new compromised versions are the highest-value contributions.

**To add a new known-compromised version**, update `KNOWN_BAD` in the script:
```python
"@example/package": {"bad": ["1.2.3"], "waves": ["Wave6-YYYY"], "advisories": ["GHSA-..."]},
```

**To add a pattern**, add a tuple to `MALICIOUS_PATTERNS`:
```python
(r"your_regex", "Human-readable description", "CRITICAL|HIGH|MEDIUM|LOW"),
```

Then add an exemplar to `tests/test_patterns.py::EXEMPLARS` (the test suite refuses a pattern without one).

**Requirements for any IOC PR:**
- Source URL in the comment above the new entry. Authoritative sources only — see `CLAUDE.md § 4.7`.
- `--self-test` must still pass 6/6.
- The calibration baseline (above) must still hold.
- `python -m ruff check . && python -m pytest -q` must be green.

Unsigned additions will not be merged — this keeps the signature set auditable and prevents attacker IOC poisoning via PRs.

---

## Architecture (one-line)

Single Python file. Stdlib only. Sentinel-bracketed reversibility for every system modification. Patterns calibrated against named packages. Test suite verifies invariants. See `CLAUDE.md` for the full breakdown.

---

## References

- **CISA** — `https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem`
- **GitHub Advisory Database** — `https://github.com/advisories`
- **NIST NVD** — `https://nvd.nist.gov/`
- **OSV** — `https://osv.dev/`
- **Datadog IOC repo** — `https://github.com/DataDog/indicators-of-compromise/tree/main/shai-hulud-2.0`
- **Datadog Security Labs** — `https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/`
- **Wiz** — `https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised`
- **StepSecurity** — `https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised`
- **Snyk** — `https://snyk.io/blog/tanstack-npm-packages-compromised/`
- **Palo Alto Unit 42** — `https://unit42.paloaltonetworks.com/npm-supply-chain-attack/`
- **OX Security** — `https://www.ox.security/blog/shai-hulud-here-we-go-again-170-packages-hit-across-npm-pypi/`

---

## License

[GPL-3.0-or-later](LICENSE). See [SECURITY.md](SECURITY.md) for disclosure policy.

This is a **defensive security tool**. The source contains pattern signatures and synthetic infection artefacts (used by `--self-test`) that may be flagged by static-analysis tools and AV engines. These flags are false positives in this context — see `SECURITY.md § A note on the project's content`.
