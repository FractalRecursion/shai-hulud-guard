# shai_hulud_guard — Quick Start

> **Current version: v2.0.0** — interactive scanner, auto-fixer, hardening assistant, and LLM diagnosis reporter.
> See [v1.1 reference](#v11--previous-version) at the bottom for the flag-based CLI.

---

## What it is

A single-file Python tool that walks you through detecting, removing, and preventing the **Shai-Hulud npm supply-chain worm** (all waves, September 2025 → present). No installation required. No external dependencies. Zero code execution from target packages.

---

## Requirements

- Python 3.8+ (standard library only — zero `pip install`)
- Internet access for pre-install checks (queries npm registry)
- Linux, macOS, or Windows

---

## Install and run

**Option A — run directly**
```bash
curl -O https://raw.githubusercontent.com/<your-repo>/main/shai_hulud_guard.py
python shai_hulud_guard.py
```

**Option B — shell installer (Linux/macOS)**
```bash
bash install.sh
shai_hulud_guard   # works from anywhere after restart
```

**Option C — Windows**
```
install.bat        # installs to %APPDATA%, adds to PATH
```

**Option D — prebuilt binary (no Python needed)**
```bash
# Linux x86-64:
chmod +x dist/shai_hulud_guard_linux_x86_64
./dist/shai_hulud_guard_linux_x86_64

# Build for your OS:
pip install pyinstaller
pyinstaller --onefile --name shai_hulud_guard shai_hulud_guard.py
```

---

## The session flow

Launch and the tool guides you through a complete session:

```
SCAN (6 checks) → VIEW FINDINGS → AUTO-FIX (100% safe) → PROTECT (tradeoffs disclosed) → DIAGNOSE (LLM report)
```

```bash
python shai_hulud_guard.py              # scan current directory
python shai_hulud_guard.py --path ~/app # scan a specific project
```

---

## Interactive menu map

```
Main menu
├── [1] Full scan
│   └── Post-scan menu
│       ├── [D] Detailed findings (paths, patterns, script content)
│       ├── [F] Auto-fix           ← daemon removal + payload file deletion
│       ├── [P] Proactive protections (4 options, each with tradeoffs)
│       ├── [R] Diagnosis report   → save .txt and paste into LLM
│       ├── [C] Pre-install check for a package
│       ├── [I] Incident response guide
│       └── [M] Main menu
├── [2] Pre-install check
├── [3] Incident response guide
└── [Q] Quit
```

---

## Non-interactive (scripts and CI)

```bash
python shai_hulud_guard.py --check lodash
python shai_hulud_guard.py --check @tanstack/react-router@1.169.5
# returns exit 0 (clean/low risk) or prints risk score and findings
```

---

## What the scan checks

| # | Check | What it catches |
|---|---|---|
| 1 | **Persistence daemon** | `gh-token-monitor` service file — definitive infection confirmation |
| 2 | **package.json audit** | Confirmed bad versions; non-registry deps bypassing `--ignore-scripts` |
| 3 | **Lock file + npmrc** | Missing lock file; no age-gate configured |
| 4 | **node\_modules scan** | Payload filenames; malicious lifecycle script patterns |
| 5 | **Credential inventory** | Which credential files the worm targets are on disk (names only) |
| 6 | **GitHub Actions audit** | `pull_request_target` + cache (Wave 5 entry); OIDC scope; tag-pinned actions |

---

## Auto-fix — what gets removed automatically

Criterion: artefacts with no legitimate use case, 100% certainty, confirmed per-item before deletion.

| What | Action |
|---|---|
| `gh-token-monitor` daemon file | Stop service + delete file |
| Payload files in node\_modules | Delete file |

Credential rotation requires authentication — listed as manual steps only.

---

## 4 proactive protections

Each disclosed with benefit + tradeoffs before you confirm.

| Protection | Tradeoff |
|---|---|
| Age-gate wrapper (`npm_safe_install.py`) | Must use wrapper instead of `npm install` |
| `save-exact=true` in npm config | Upgrades require manual version bumps |
| `ignore-scripts=true` in project `.npmrc` | Native addons need per-package override |
| GitHub Actions SHA-pinning report | Report only — you edit the YAML |

---

## Diagnosis report

Select **[R]** after a scan. Saves `shai_hulud_report_YYYYMMDD_HHMMSS.txt`.

Paste the full file into Claude or another LLM. Contains:
- System info (OS, Node, npm, git versions)
- All findings with full detail
- Installed packages flagged against known-target list
- Credential files present (names only — no values)
- Actions taken + protections applied
- 7 pre-written questions for LLM guidance

---

## Risk score (`--check`)

| Score | Action |
|---|---|
| 0 | No indicators — read limitations before proceeding |
| 1–14 | Low — manual review recommended |
| 15–39 | Moderate — verify independently |
| 40–69 | High — do not install without investigation |
| 70–100 | Critical — do not install |

---

## If the daemon is found

Token revocation triggers `rm -rf ~/`. The daemon self-destructs after 24 hours.

**Correct sequence: ISOLATE → REMOVE DAEMON (use [F]) → REVOKE CREDENTIALS**

Use **[I]** for full manual incident guide.

---

## Limitations

- Novel obfuscation not in the IOC database evades pattern detection
- Known-bad version list lags zero-day attack windows
- Runtime-fetched payloads (downloaded after install) are not caught
- Does not replace Socket.dev, Snyk, or Wiz for continuous registry monitoring

Authoritative IOC list: `https://github.com/DataDog/indicators-of-compromise/tree/main/shai-hulud-2.0`

---
---

## v1.1 — Previous version

> Retained as changelog reference. v1.1 used explicit CLI flags. All detection logic carried forward and expanded in v2.0.

**Breaking changes v1.1 → v2.0:**
- `--scan` flag removed (use interactive menu option 1)
- `--incident` flag removed (use interactive menu option 3)
- `--check` retained as the only non-interactive flag
- `--path` retained as a modifier

**New in v2.0:**
- Interactive session replaces flag-based flow
- Live progress spinner per check
- Structured findings with auto-fix functions attached
- Auto-fix: daemon removal + payload file deletion, per-item confirm
- 4 proactive protections with tradeoff disclosure before each
- LLM-ready diagnosis report generator
- `install.sh` + `install.bat` installers
- PyInstaller binary distribution (`dist/`)
- Corrected: `min-release-age=7d` is not a valid npm 10 config — replaced with `npm_safe_install.py` wrapper

### v1.1 commands

```bash
python shai_hulud_guard.py --scan
python shai_hulud_guard.py --scan --path ~/projects/my-app
python shai_hulud_guard.py --check @tanstack/react-router
python shai_hulud_guard.py --check @tanstack/react-router@1.169.5
python shai_hulud_guard.py --incident
python shai_hulud_guard.py --version
```

### v1.1 checks (same 6, same logic)

| # | Check |
|---|---|
| 1 | Persistence daemon |
| 2 | package.json audit |
| 3 | Lock file + npmrc hygiene |
| 4 | node\_modules deep scan |
| 5 | Credential file inventory |
| 6 | GitHub Actions audit |

### v1.1 risk score

| Score | Verdict |
|---|---|
| 0 | Clean |
| 1–14 | Low |
| 15–39 | Moderate |
| 40–69 | High |
| 70–100 | Critical |

### v1.1 daemon warning

Do not revoke tokens before daemon removal. Run `--incident` for the sequence.
