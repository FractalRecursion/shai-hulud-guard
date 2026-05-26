# shai_hulud_guard — Quick Start

> **Current version: v2.4.0** — single-file, stdlib-only CLI scanner, hardener, and
> proactive-defence tool for the Shai-Hulud npm / PyPI supply-chain worm family.
> Flag-based (no interactive menu — fully scriptable / CI-friendly).

For the full reference see **[README.md](README.md)**; for the design rationale see **[docs/DESIGN.md](docs/DESIGN.md)**.

---

## Requirements

- **Python 3.8+** — standard library only, zero `pip install` for the runtime tool.
- **Internet access** for pre-install checks (queries the npm / PyPI registries only — no telemetry).
- **Linux, macOS, or Windows.**

---

## Get it

**Option A — run the script directly (recommended)**
```bash
curl -O https://raw.githubusercontent.com/FractalRecursion/shai-hulud-guard/main/shai_hulud_guard.py
python shai_hulud_guard.py --self-test      # 6/6 assertions, ~2s, proves it works
```

**Option B — prebuilt single-file binary (no Python needed)**
Download the binary for your OS from the [Releases page](https://github.com/FractalRecursion/shai-hulud-guard/releases/latest)
(each asset ships with a `SHA256SUMS` file + SLSA build provenance — verify before running), or build it yourself:
```bash
pip install -e ".[dev]"   # installs PyInstaller, pytest, ruff
python build.py            # -> dist/shai_hulud_guard[.exe]
```

---

## The lifecycle — one flag per stage

```
   PREVENT          DETECT             RESPOND          HARDEN
   ───────          ──────             ───────          ──────
   --check     →    --scan       →    --patch     →    --protect
   --check-pypi     --lockcheck       --verify         --unprotect
                    --self-test       --diagnose
```

```bash
# PREVENT — vet a package BEFORE installing (exit 1 if risk ≥ 40 → blocks install in a wrapper)
python shai_hulud_guard.py --check        <pkg>[@<version>]      # npm
python shai_hulud_guard.py --check-pypi   <pkg>[==<version>]     # PyPI

# DETECT — inspect a project you already have
python shai_hulud_guard.py --scan      --path .
python shai_hulud_guard.py --lockcheck --path .                  # audit lockfile entries
python shai_hulud_guard.py --diagnose  --path .                  # writes an LLM-paste-ready report

# RESPOND — remediate (token-revocation ordering is enforced; see warning below)
python shai_hulud_guard.py --patch --path .                      # generate per-case remediation scripts
python shai_hulud_guard.py --patch --path . --auto               # run them after confirmation
python shai_hulud_guard.py --incident                            # 8-step incident-response guide

# HARDEN — install reversible proactive defences (use a disposable path while testing!)
python shai_hulud_guard.py --protect --path .  [--setup-alias] [--setup-npmrc] [--setup-cron]
python shai_hulud_guard.py --unprotect --path .                  # removes exactly what --protect added

# Add --json to any mode for machine-readable output (CI / LLM ingestion)
python shai_hulud_guard.py --check react --json
```

---

## What `--scan` checks

| # | Check | What it catches |
|---|---|---|
| 1 | **Persistence daemon** | `gh-token-monitor` service/agent — definitive infection confirmation |
| 2 | **Manifest audit** | Confirmed-bad versions (`KNOWN_BAD`); non-registry deps; lifecycle hooks |
| 3 | **Lockfile + `.npmrc`** | Tampered lockfile entries; integrity-mismatch signals |
| 4 | **`node_modules` scan** | Payload filenames (`router_init.js`, …); malicious lifecycle-script patterns |
| 5 | **Credential inventory** | Which credential files the worm targets exist on disk (**names only — never read**) |
| 6 | **GitHub Actions audit** | `pull_request_target` + cache (Wave 5 vector); OIDC scope; unpinned actions |

`--check` / `--check-pypi` additionally fetch the package's registry metadata **and** its tarball/wheel
(read **in memory** — nothing is ever extracted to disk or executed) and score the contents.

---

## Risk score & exit code

| Score | Verdict | Process exit |
|---|---|---|
| 0 | Proceed with caution (a 0 is **not** a clean guarantee — see Limitations) | 0 |
| 1–14 | Low — manual review recommended | 0 |
| 15–39 | Moderate — verify independently | 0 |
| 40–69 | **High — investigate before installing** | **1** |
| 70–100 | **CRITICAL — do not install** | **1** |

The non-zero exit at ≥ 40 is what lets the generated `npm_safe` / `pip_safe` wrappers **block** an install.

---

## ⚠ If the persistence daemon is found

The worm's `gh-token-monitor` daemon polls GitHub every ~60 s and triggers **`rm -rf ~/`** if it detects a
token revocation. **Never revoke or rotate credentials before the daemon is removed.**

**Correct order:** `STOP → ISOLATE → IMAGE → REMOVE DAEMON → ROTATE CREDS → AUDIT → REBUILD → REPORT`

`--patch` and `--incident` enforce this ordering for you. Run `--incident` for the full guide.

---

## Limitations (read before trusting a clean result)

- Novel obfuscation with no overlap to known IOCs evades pattern detection.
- The known-bad list lags the zero-day window (typically 2–8 h before public IOC lists update).
- Payloads fetched **after** install (not present in the tarball) are not caught.
- A **score of 0 is not a guarantee of safety** — it means no known indicator matched.
- This is a focused worm scanner, not a replacement for Socket.dev / Snyk / Wiz continuous monitoring.

Authoritative IOC sources are listed in [README.md](README.md#sources) and `CLAUDE.md §4.7`.

---

*Looking for the old interactive (v1.1 / v2.0) CLI? It is archived, unmaintained, in [`legacy/`](legacy/). v2.4 is the one canonical tool.*
