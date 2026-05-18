# shai_hulud_guard

> **Current version: v2.0.0** — interactive scanner, auto-fixer, hardening assistant, and LLM diagnosis reporter.
> Zero external dependencies. Python 3.8+. Linux / macOS / Windows.

---

## What it does

`shai_hulud_guard` detects, removes, and helps prevent the **Shai-Hulud npm supply-chain worm** — a self-replicating worm that has attacked npm and PyPI ecosystems across five documented waves (September 2025 → present), attributed to threat actor **TeamPCP** (DeadCatx3, PCPcat, ShellForce, CipherForce).

A single session covers the full response loop:

```
SCAN (6 checks) → FINDINGS → AUTO-FIX (safe) → PROTECT (tradeoffs) → DIAGNOSE (LLM report)
```

---

## Threat background

### Attack timeline

| Wave | Date | Entry vector | Scale |
|---|---|---|---|
| Wave 1 | September 2025 | Compromised maintainer credentials | 500+ packages |
| Wave 2 | November 2025 | CI/CD pipeline injection | 796 packages, 1,092 versions |
| Wave 3 | March 2026 | Aqua Security Trivy packages | Targeted |
| Wave 4 | April 2026 | SAP npm packages; Bitwarden CLI | Targeted |
| Wave 5 (Mini) | May 11, 2026 | GitHub Actions cache poisoning + OIDC extraction | 172 packages, 403 versions, 518M cumulative downloads |

Wave 5 introduced **valid SLSA Build Level 3 provenance attestations on malicious packages** — bypassing all standard verification tools.

### Attack chain

1. Fork target repo → open PR triggering `pull_request_target` workflow → poison Actions cache
2. Legitimate release workflow restores poisoned cache → binaries extract GitHub Actions OIDC token from runner memory (`/proc/<pid>/mem`)
3. `preinstall` hook installs Bun silently → runs `router_init.js` (~2.3 MB obfuscated) — 10 parallel credential collectors
4. Sweeps: npm tokens, GitHub PATs, AWS/GCP/Azure keys, SSH keys, `.gitconfig`, `.npmrc`
5. Exfiltrates via 3 channels simultaneously: `git-tanstack[.]com`, Session network, GitHub API dead drops
6. Uses stolen npm token to publish infected versions of up to 100 of the victim's packages → self-propagates
7. Installs `gh-token-monitor` daemon (Linux systemd / macOS LaunchAgent) — polls GitHub every 60s, triggers `rm -rf ~/` if any token is revoked

### Why standard defences failed (Wave 5)

| Defence | Failure mode |
|---|---|
| SLSA BL3 provenance | Injected before provenance was generated — attestation was valid |
| 2FA on maintainer accounts | OIDC token extracted from CI runner memory, not from the account |
| `npm audit` | Designed for CVEs, not malicious code injection |
| `--ignore-scripts` on parent | Git/file transitive deps still run `prepare` hooks |
| Trusting well-known packages | TanStack, Mistral AI, UiPath, OpenSearch all compromised |

---

## Installation

**No installation required for the Python script.** Run directly with Python 3.8+.

```bash
# Run directly
python shai_hulud_guard.py

# Shell installer (Linux/macOS) — installs to ~/.local/bin
bash install.sh

# Windows installer — installs to %APPDATA%, adds to PATH
install.bat

# Prebuilt Linux binary (no Python needed)
chmod +x dist/shai_hulud_guard_linux_x86_64
./dist/shai_hulud_guard_linux_x86_64

# Build for your platform
pip install pyinstaller
pyinstaller --onefile --name shai_hulud_guard shai_hulud_guard.py
```

---

## Usage

```bash
python shai_hulud_guard.py              # interactive — scan current directory
python shai_hulud_guard.py --path DIR   # interactive — scan a specific project
python shai_hulud_guard.py --check PKG  # non-interactive pre-install check
python shai_hulud_guard.py --version
```

---

## Interactive flow (v2.0)

### Main menu

```
[1]  Full scan
[2]  Pre-install check (type a package name)
[3]  Incident response guide
[Q]  Quit
```

### After scan

```
[D]  View detailed findings
[F]  Auto-fix safe items         ← only shown if fixable items found
[P]  Set up proactive protections
[R]  Generate diagnosis report   ← LLM-ready .txt file
[C]  Pre-install check
[I]  Incident response guide
[M]  Return to main menu
```

---

## Scan — 6 checks explained

**Check 1 — Persistence daemon**
Looks for `gh-token-monitor` at exact documented paths:
- Linux: `~/.config/systemd/user/gh-token-monitor.service`
- macOS: `~/Library/LaunchAgents/com.user.gh-token-monitor.plist`

If found: definitive active infection. Tool warns immediately — do not revoke tokens before daemon removal.

**Check 2 — package.json audit**
Loads all dependency sections (`dependencies`, `devDependencies`, `peerDependencies`, `optionalDependencies`). Matches against known-bad version database and high-value-target list. Flags any non-registry sources (`git:`, `github:`, `bitbucket:`, `file:`) — these run `prepare` hooks regardless of `--ignore-scripts` on the parent.

**Check 3 — Lock file and npmrc hygiene**
Detects missing lock file (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`). Checks global `~/.npmrc` for age-gate configuration. Reports missing npm security settings.

**Check 4 — node\_modules deep scan**
Walks all installed packages including scoped namespaces. Checks for known payload filenames and runs the full IOC pattern engine against every lifecycle script (`preinstall`, `install`, `postinstall`, `prepare`).

**Check 5 — Credential file inventory**
Lists credential files on disk that the worm's documented sweep targets. File names only — no contents read or transmitted. Scopes the rotation required if infection is confirmed.

**Check 6 — GitHub Actions workflow audit**
If `.github/workflows/` exists: flags `pull_request_target` + cache combination (exact Wave 5 entry vector), `id-token: write` at workflow level instead of job level, and third-party actions pinned by tag instead of commit SHA.

---

## IOC signature coverage

### Payload filenames (definitive indicators)

| Filename | Waves |
|---|---|
| `router_init.js` | All waves — core payload (~2.3 MB) |
| `setup_bun.js` | Waves 2–5 — Bun installer stub |
| `bun_environment.js` | Wave 2 |
| `setup.mjs` | Wave 1 — ESM variant |

### Pattern signatures (29 across 4 risk levels)

| Category | Risk | Examples |
|---|---|---|
| Worm identity | CRITICAL | `Shai-Hulud`, `TeamPCP`, `gh-token-monitor` campaign tags |
| Destructive payload | CRITICAL | `rm -rf ~/`, `rm -rf $HOME`, Windows home-wipe |
| C2 infrastructure | CRITICAL | `git-tanstack.com`, `webhook.site/<uuid>` |
| Token literals | CRITICAL | `ghp_<36>`, `gho_<36>`, `npm_<36>` |
| CI memory extraction | CRITICAL | `/proc/<pid>/mem`, OIDC token env vars |
| Persistence | CRITICAL | LaunchAgent paths, systemd user service paths |
| Cloud credentials | HIGH | GCP ADC path, `AWS_SECRET_ACCESS_KEY`, Azure secrets |
| Bun injection | HIGH | `bun.sh/install` in lifecycle scripts |
| GitHub API abuse | HIGH | `api.github.com/user/repos` in scripts |
| Obfuscation | HIGH/MEDIUM | `eval(atob(...))`, ASCII chars as `\u00XX` escapes |
| CI/CD misconfiguration | MEDIUM | `pull_request_target`, broad `restore-keys` |

### Known-compromised packages

| Package | Confirmed bad version(s) | Waves |
|---|---|---|
| `@tanstack/react-router` | `1.169.5` | Wave 5 — May 2026 |
| `@tanstack/router` | `1.169.5` | Wave 5 — May 2026 |
| `@tanstack/react-query` | (scrutiny flag) | Wave 5 — May 2026 |
| `intercom-client` | `7.0.4` | Wave 5 — May 2026 |
| `guardrails-ai` (PyPI) | `0.10.1` | Wave 5 — May 2026 |
| `mistralai` (PyPI) | `2.4.6` | Wave 5 — May 2026 |
| `@bitwarden/cli` | (scrutiny flag) | Wave 4 — April 2026 |
| `tinycolor2` | (scrutiny flag) | Wave 1 — September 2025 |
| `@asyncapi/cli` | (scrutiny flag) | Wave 2 — November 2025 |

Authoritative source: `https://github.com/DataDog/indicators-of-compromise/tree/main/shai-hulud-2.0`

---

## Auto-fix

Only artefacts with no legitimate use case are offered for removal, confirmed individually.

| What | Platform | Method |
|---|---|---|
| `gh-token-monitor` daemon | Linux | `systemctl --user stop/disable` + file deletion |
| `gh-token-monitor` plist | macOS | `launchctl unload` + file deletion |
| Payload files in `node_modules` | All | `os.remove()` |

After auto-fix: manual credential rotation steps are listed with exact URLs and commands. Token revocation is never automated — it requires authentication and the daemon must be confirmed removed first.

---

## Pre-install check — 5 steps

```bash
python shai_hulud_guard.py --check @tanstack/react-router
python shai_hulud_guard.py --check @tanstack/react-router@1.169.5
```

| Step | What it checks |
|---|---|
| 1 | Registry metadata: publish age, maintainer count |
| 2 | Known-bad version database match |
| 3 | Lifecycle scripts from registry metadata — 29-pattern IOC scan |
| 4 | Dependency sources — flags non-registry deps |
| 5 | Tarball download + SHA-512 integrity + deep file scan |

**Risk score:**

| Score | Level | Action |
|---|---|---|
| 0 | Clean | No indicators — read limitations |
| 1–14 | Low | Manual review |
| 15–39 | Moderate | Verify independently |
| 40–69 | High | Investigate before installing |
| 70–100 | Critical | Do not install |

Score weights: CRITICAL finding +45–50, HIGH +15–20, published <6h +40, integrity failure +100.

---

## Proactive protections

Four protections, each presented with full benefit and tradeoff disclosure before confirm.

**Protection 1 — Age-gate wrapper**
Writes `npm_safe_install.py` to your project — a drop-in wrapper that checks publish date before calling `npm install`. Packages newer than 7 days are blocked.
- `npm` does not natively support `min-release-age` as a config option (verified npm 10)
- Tradeoff: must use `python npm_safe_install.py <pkg>` instead of `npm install <pkg>`

**Protection 2 — `save-exact=true`**
Pins exact versions in package.json instead of semver ranges.
- Tradeoff: version upgrades require explicit bumps

**Protection 3 — `ignore-scripts=true` in project `.npmrc`**
Blocks all lifecycle scripts from running on `npm install` in this project.
- Tradeoff: packages requiring build steps (native addons, Electron, TypeScript compile) won't build until re-enabled with `--ignore-scripts=false`

**Protection 4 — GitHub Actions SHA-pinning report**
Generates `shai_hulud_pin_actions.txt` listing all tag-pinned action references that need SHA updating.
- Tradeoff: report only — you edit the YAML files

---

## Diagnosis report (LLM-ready)

Select **[R]** after a scan. Saved to `shai_hulud_report_YYYYMMDD_HHMMSS.txt`.

Paste the full file into Claude or another LLM for personalised incident guidance. Contains:
- System information (OS, Node.js, npm, git versions, CI environment)
- Full findings list with paths, matched patterns, script content
- All installed packages flagged against known-target list
- Credential files present on disk (names only — no values)
- Auto-fixes applied + protections status
- 7 pre-written questions for the LLM to address

---

## Incident response guide

Select **[I]** for the full guide. Summary:

```
STEP 1 — STOP:    Do NOT revoke tokens (daemon triggers rm -rf ~/)
STEP 2 — ISOLATE: Disconnect from network
STEP 3 — IMAGE:   Forensic snapshot before cleanup
STEP 4 — REMOVE:  Delete daemon (use [F] or manual commands)
STEP 5 — ROTATE:  Now revoke: GitHub, npm, AWS/GCP/Azure, SSH
STEP 6 — AUDIT:   Check npm publish history for unauthorised releases
STEP 7 — REBUILD: Wipe OS, rebuild from clean image
STEP 8 — REPORT:  npm security@npmjs.com | CISA cisa.gov/reporting
```

---

## Safe install workflow

```bash
# 1 — Install without executing lifecycle scripts
npm install <package>@<version> --ignore-scripts

# 2 — Inspect declared scripts
cat node_modules/<pkg>/package.json | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print(json.dumps(d.get('scripts',{}),indent=2))"

# 3 — Search for payload filenames
find node_modules/<pkg> -name "router_init.js" -o -name "setup_bun.js"

# 4 — Re-enable postinstall only after manual review
# npm rebuild <pkg>@<version>
```

---

## Systemic hardening

### npm

```bash
npm config set save-exact=true      # exact version pinning
# Use npm ci (not npm install) in all CI pipelines
# npm ci --ignore-scripts in fully automated pipelines
```

### GitHub Actions

```yaml
# id-token: write at job level only — never at workflow level
permissions:
  id-token: none        # workflow default

jobs:
  publish:
    permissions:
      id-token: write   # only this job

# Pin actions by commit SHA, not tag
# Bad:  uses: actions/checkout@v4
# Good: uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683

# Use pull_request (fork-sandboxed) not pull_request_target for untrusted code
```

---

## Honest limitations

Five gaps — none softened:

1. **Pattern evasion** — each Shai-Hulud wave introduced new obfuscation. Zero-day variants produce zero pattern findings. This is not a theoretical concern.

2. **Runtime-fetched payloads** — packages that download and execute code at runtime after install are not caught by the tarball scan. The lifecycle script engine partially mitigates by flagging outbound fetch patterns.

3. **Known-bad list latency** — active attack windows (2–8h) precede public disclosure. During this window the tool can detect anomalies (publish age, tarball size, suspicious patterns) but cannot confirm compromise from the database.

4. **Provenance bypass** — Wave 5 confirmed that valid SLSA BL3 attestations don't indicate clean code when the build pipeline itself is compromised. This tool does not verify provenance.

5. **`--ignore-scripts` bypass** — git/file-sourced transitive dependencies run `prepare` hooks unconditionally. The scanner flags these in Check 2 and pre-install Check 4, but the root mitigation requires auditing the full dependency tree.

---

## Contributing

IOC updates and confirmed new compromised versions are the highest-value contributions.

To add a new known-compromised version, update `KNOWN_BAD` in the script:
```python
"@example/package": {"bad": ["1.2.3"], "waves": ["Wave6-YYYY"]},
```

To add a pattern, add a tuple to `MALICIOUS_PATTERNS`:
```python
(r"your_regex", "Human-readable description", "CRITICAL|HIGH|MEDIUM|LOW"),
```

**Requirement:** pull requests adding patterns must include a source URL (post-mortem, CISA advisory, or IOC repo reference). Unsigned additions will not be merged — this keeps the signature set auditable and prevents attacker IOC poisoning via PRs.

---

## References

- CISA: `https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem`
- Datadog Security Labs: `https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/`
- Datadog IOC repo: `https://github.com/DataDog/indicators-of-compromise/tree/main/shai-hulud-2.0`
- Wiz: `https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised`
- StepSecurity: `https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised`
- Snyk: `https://snyk.io/blog/tanstack-npm-packages-compromised/`
- Palo Alto Unit 42: `https://unit42.paloaltonetworks.com/npm-supply-chain-attack/`
- OX Security: `https://www.ox.security/blog/shai-hulud-here-we-go-again-170-packages-hit-across-npm-pypi/`

---

## License

GPL-3.0

---
---

## v1.1 — Previous version (changelog)

> Retained as changelog reference. All v1.1 detection logic is present and expanded in v2.0.

### What changed v1.1 → v2.0

**Breaking:**
- `--scan` flag removed — replaced by interactive menu option `[1]`
- `--incident` flag removed — replaced by interactive menu option `[3]`
- `--check` retained as the only non-interactive flag
- `--path` retained as a modifier

**Added:**
- Interactive session driven by numbered menus
- Live spinner progress per scan check (overwrites line in-place)
- Structured `Finding` dataclass with attached fix functions
- Auto-fix flow: daemon removal + payload file deletion, confirmed per-item
- 4 proactive protections with full benefit + tradeoff disclosure before each
- LLM-ready diagnosis report generator (`shai_hulud_report_YYYYMMDD_HHMMSS.txt`)
- `install.sh` — Linux/macOS shell installer
- `install.bat` — Windows installer (adds to user PATH)
- PyInstaller binary distribution (`dist/`)
- `npm_safe_install.py` age-gate wrapper (generated by Protection 1)

**Fixed:**
- `min-release-age=7d` is NOT a valid npm 10 config option (returns `npm error: not a valid npm option`). Was incorrectly documented and applied in v1.1. Replaced with the `npm_safe_install.py` wrapper.

### v1.1 command reference

```bash
python shai_hulud_guard.py --scan
python shai_hulud_guard.py --scan --path ~/projects/my-app
python shai_hulud_guard.py --check @tanstack/react-router
python shai_hulud_guard.py --check @tanstack/react-router@1.169.5
python shai_hulud_guard.py --incident
python shai_hulud_guard.py --version
```

### v1.1 checks (same 6 checks, same detection logic)

| # | Check |
|---|---|
| 1 | Persistence daemon — `gh-token-monitor` |
| 2 | package.json — known bad versions; non-registry deps |
| 3 | Lock file + npmrc hygiene |
| 4 | node\_modules — payload filenames; lifecycle patterns |
| 5 | Credential file inventory |
| 6 | GitHub Actions — `pull_request_target` + cache; OIDC scope; tag pins |

### v1.1 pre-install check (5 steps — identical to v2.0)

| Step | Check |
|---|---|
| 1 | Registry metadata (age, maintainers) |
| 2 | Known-bad version DB |
| 3 | Lifecycle scripts from registry metadata |
| 4 | Dependency source validation |
| 5 | Tarball download + SHA-512 + deep scan |

### v1.1 risk score

| Score | Verdict |
|---|---|
| 0 | No indicators |
| 1–14 | Low |
| 15–39 | Moderate |
| 40–69 | High |
| 70–100 | Critical |

### v1.1 daemon warning

Do not revoke tokens before daemon removal. Run `--incident` for the exact sequence.
