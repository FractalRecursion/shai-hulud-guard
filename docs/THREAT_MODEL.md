# Threat model — Shai-Hulud worm family vs. `shai_hulud_guard`

This document maps the **attack chain** of each documented Shai-Hulud wave
(September 2025 → present) to the **defensive features** in this tool that
catch each step. It exists for two audiences:

1. **Reviewers** assessing whether the defences are coherent and proportionate
   to the threat.
2. **Operators** trying to understand which control fired during an incident.

It is a complement, not a substitute, to the [Datadog IOC repo][datadog] and
the [CISA advisory][cisa].

[datadog]: https://github.com/DataDog/indicators-of-compromise/tree/main/shai-hulud-2.0
[cisa]:    https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem

---

## Threat actor

Attributed (as of public disclosure): **TeamPCP** — also active under aliases
**DeadCatx3**, **PCPcat**, **ShellForce**, **CipherForce**.

Operating pattern: self-replicating worm in the npm and (since Wave 5) PyPI
ecosystems. Five publicly-documented waves so far. Each wave reused most of
the previous wave's tooling but added a novel entry vector — see the table
below.

---

## Wave timeline

| Wave | Date | Entry vector | Scale | Novelty |
|---|---|---|---|---|
| **Wave 1** | September 2025 | Compromised maintainer credentials | 500+ packages | Initial `gh-token-monitor` daemon |
| **Wave 2** | November 2025 | CI/CD pipeline injection | 796 packages, 1 092 versions | `setup_bun.js` Bun-installer stub |
| **Wave 3** | March 2026 | Aqua Security / Trivy packages | Targeted | Direct security-tool subversion |
| **Wave 4** | April 2026 | SAP npm packages; Bitwarden CLI | Targeted | Targeting credential-management tooling |
| **Wave 5 (Mini)** | May 2026 | GitHub Actions cache poisoning + OIDC extraction | 172 packages, 403 versions, **518 M cumulative downloads** | **Valid SLSA-BL3 provenance on malicious packages** |

---

## The attack chain — step by step, mapped to defences

The chain below describes Wave 5 (the most sophisticated) explicitly; earlier
waves used subsets of these steps. The right-hand columns identify which
`shai_hulud_guard` check fires at that step.

| # | Step | What the worm does | Caught by |
|:-:|---|---|---|
| **1** | **Entry** | Fork target repo; open a PR that triggers `pull_request_target` workflow → can write to the Actions cache. | `--scan` **CHECK 6** flags any workflow combining `pull_request_target` + `actions/cache`. (Wave 5 entry vector.) |
| **2** | **Cache poisoning** | The poisoned PR writes a tampered build artefact into the GitHub Actions cache. The legitimate release workflow later restores this cache and uses the tampered artefact in its build. | Out of scope at scan time — the poisoning lives in the *attacker's* fork. The downstream signal is the unusual lifecycle script or the bundled binary in the *victim's* tarball, caught by `--check` STEPs 3 + 5. |
| **3** | **OIDC token theft** | Restored cache contains binaries that read GitHub Actions OIDC token from runner memory (`/proc/<pid>/mem`). Token grants short-lived but real publish privileges. | Pattern `r"/proc/\d+/mem"` in `MALICIOUS_PATTERNS` flags this at CRITICAL when seen inside a lifecycle script or tarball file. |
| **4** | **Bun install** | `preinstall` hook downloads and silently installs the Bun runtime — needed to execute the obfuscated payload faster than Node. | `--check` STEP 3 flags lifecycle scripts; pattern `bun\.sh/install` → HIGH. STEP 5 deep-scans the tarball and re-runs the pattern engine against every file. |
| **5** | **Payload execution** | `router_init.js` (~2.3 MB, obfuscated) runs in the lifecycle script context. It launches 10 parallel credential collectors. | `MALICIOUS_FILENAMES` set hard-blocks `router_init.js` regardless of contents — every tarball is scanned (`--check` STEP 5). |
| **6** | **Credential sweep** | Sweeps in parallel: **npm tokens, GitHub PATs, AWS/GCP/Azure keys, SSH keys, `.gitconfig`, `.npmrc`**. | `--scan` **CHECK 5** lists the presence of these files (paths only — never reads contents). The patterns `\.aws/credentials`, `application_default_credentials\.json`, `\.ssh/(id_rsa|id_ed25519|id_ecdsa)\b` flag any source code that reads them. |
| **7** | **Exfiltration** | Three parallel channels: `git-tanstack[.]com` (DNS C2), Session network, GitHub API dead drops in attacker-controlled repos. | C2 patterns in `MALICIOUS_PATTERNS`: `git-tanstack\.com` → CRITICAL, `webhook\.site/<uuid>` → CRITICAL, Session network domains → HIGH. |
| **8** | **Self-propagation** | Stolen npm token is used to publish infected versions of up to 100 of the victim's own packages. | Detection happens *post-publication*. `--check` and `--check-pypi` on those infected versions then trigger via `KNOWN_BAD` (after the IOC list is updated) and via fresh-publish-age weighting (+40 for <6 h, +25 for <24 h). |
| **9** | **Persistence** | Installs `gh-token-monitor` daemon (systemd / LaunchAgent / Task Scheduler). Polls GitHub every 60 s; on token revocation, executes `rm -rf ~/` (or Windows equivalent). | `--scan` **CHECK 1** queries the exact documented persistence paths; on Windows queries Task Scheduler + Startup folder by known names. `KNOWN_BAD["gh-token-monitor"]` ensures it's never accidentally trusted as a normal dependency. |
| **10** | **Kill switch** | If the operator panics and revokes the npm token, the daemon detects it within 60 s and triggers home-directory wipe. | `--incident` STEP 1 ("STOP — do NOT revoke tokens yet") and the patch flow's ordering invariant make this unreachable when the operator follows the documented response. See `--incident` for the full 8-step playbook. |

---

## Why the standard defences failed (Wave 5)

| Defence | Why it failed | What `shai_hulud_guard` adds |
|---|---|---|
| SLSA Build Level 3 provenance | Injected *before* provenance was generated — the attestation was technically valid. | Provenance is not used as a signal. The scanner reads the actual tarball contents and checks integrity hashes (SHA-512). |
| 2FA on maintainer accounts | OIDC token was extracted from CI runner memory — the maintainer account was not directly compromised. | `--scan` flags `/proc/*/mem` reads and OIDC environment-variable patterns in workflows. |
| `npm audit` | Designed for known CVEs in legitimate code, not for malicious code injection in legitimate packages. | Tarball deep-scan + pattern engine reads the *actual* package contents. `KNOWN_BAD` cross-references confirmed-malicious *version pairs*, not generic vulnerable libraries. |
| `--ignore-scripts` on parent | Git / file / http: transitive dependencies still run `prepare` hooks unconditionally — npm has no way to forbid this. | `--check` STEP 4 flags non-registry deps as +12 each (capped at +30); the patch flow recommends removing them or moving to registry-only versions. |
| Trusting well-known packages | TanStack, Mistral AI, UiPath, Bitwarden, OpenSearch all compromised across waves 1-5. | `HIGH_VALUE_TARGETS` set treats these as warrant-higher-scrutiny regardless of `bad` list state — +15 risk and a MEDIUM finding. |

---

## What this tool does **not** defend against

Honest gaps, ordered by likelihood:

1. **Novel obfuscation.** Each wave introduced new packing/encoding to evade
   regex IOCs. A wave-N+1 payload that has no overlap with waves 1-5 patterns
   produces zero findings. Mitigated partially by `KNOWN_BAD` (once disclosed)
   and by anomaly heuristics (publish-age, maintainer-drift, semver-gap, new
   non-registry deps).
2. **Runtime-fetched payloads.** A clean tarball whose `postinstall` hook
   silently `curl`s an external blob and `eval`s it would pass the static
   scan. The lifecycle-script pattern engine catches a fetch-then-eval pair
   only when both appear *literally* in the script text.
3. **Known-bad list latency.** During the 2-8 h window between actual
   compromise and public disclosure, `KNOWN_BAD` is silent. Anomaly heuristics
   (publish-age tier) partially compensate.
4. **Provenance bypass.** This tool does not verify SLSA provenance and would
   not have been more useful if it did. The signal the worm leaves is in the
   *artefact contents*, not the attestation.
5. **State changes after scan.** `--scan` is a snapshot. A package that
   passes today and is recompromised tomorrow shows as clean until the next
   scan. `--protect --setup-cron` schedules a daily scan to bound the
   window.

A non-zero risk score is a strong signal to investigate further.
**A zero risk score is not a guarantee of safety.**

---

## Defensive feature → attack-chain mapping (reverse index)

| Feature in `shai_hulud_guard.py` | Catches step(s) | Notes |
|---|---|---|
| `MALICIOUS_FILENAMES` set | 5 | Hard-block; contents don't matter |
| `MALICIOUS_PATTERNS` (regex table) | 3, 4, 6, 7 | The bulk of detection; per-pattern citation required |
| `KNOWN_BAD` confirmed-bad versions | 8 | Hard-block at risk 100 |
| `HIGH_VALUE_TARGETS` watch-list | 8 (pre-disclosure) | +15 risk on scrutiny-only flag |
| `DAEMON_PATHS` + `check_windows_persistence()` | 9 | Per-OS persistence paths |
| `CREDENTIAL_FILES` presence check | 6 | Names only, never reads contents |
| `--check` STEP 1 publish-age tiers | 8 (window) | +40 / +25 / +10 weights |
| `--check` STEP 2.5 heuristics | 8 (pre-disclosure) | Maintainer drift, semver gap, new deps |
| `--check` STEP 4 dep-source validation | 4 | Flags non-registry deps |
| `--check` STEP 5 tarball deep-scan | 3, 4, 5, 6, 7 | In-memory; never executes |
| `--scan` CHECK 6 workflow audit | 1 | `pull_request_target` + cache combo |
| `--scan` CHECK 7 registry-config audit | (config drift) | Non-default registry → potential C2 redirect |
| `--lockcheck` integrity + resolved-URL audit | 4, 5 (downstream) | v1/v2/v3 lockfile formats |
| `--patch` infection classifier | 9 (response) | Enforces "daemon first, tokens later" |
| `--incident` 8-step playbook | 10 | Static doc; ordering is load-bearing |
| `--protect` install wrappers | 5 (pre-install) | Blocks installs of risk ≥ 40 packages |
| `--protect` SHA-pinned CI workflow | 1 | Defends future workflows |
| Typosquatting detector | (pre-Wave-1 class) | Levenshtein ≤ 2 from top-80 npm |

---

## Forward-looking — what to add next

In rough priority order, given the trajectory of the campaign:

1. **GHSA population in `KNOWN_BAD["advisories"]`.** Field is scaffolded in v2.4
   but unfilled. A future minor should look up each entry against GHSA and
   record the IDs.
2. **PyPI distinct-author / similar-author heuristic.** Wave 5 expanded to
   PyPI for the first time; the next wave is likely to do the same with
   different packages. Detect when an established package suddenly publishes
   from a previously-unseen co-maintainer.
3. **SBOM consumption.** Accept an SPDX or CycloneDX SBOM as input and
   cross-reference every component against `KNOWN_BAD`. Enables one-shot
   verification of a large dependency tree.
4. **Native-module hash check.** Wave 5's binaries were native modules with
   no source. A hash database of known-good native artefacts (from public
   tags / SLSA attestations) could enable hash-mismatch detection even
   when the source is unverifiable.
5. **OIDC-runner memory-protection probe.** A workflow-time check that
   verifies the runner blocks `/proc/<pid>/mem` access from non-root
   processes. Out of scope for a static scanner, but useful as a `--protect`
   recommendation.

These are **enhancements, not gaps**. The current feature set covers
documented waves 1-5; the items above defend against the next wave's likely
shape rather than past ones.
