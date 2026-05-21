# Security Policy

`shai_hulud_guard` is a **defensive security tool**. Its purpose is to help
developers and operators detect and respond to supply-chain compromises
in the npm and PyPI ecosystems, including the Shai-Hulud worm family
(September 2025 – present).

## A note on the project's content

This repository contains, in source form:

- **Pattern signatures** that match malicious code idioms (reverse shells,
  credential-file paths, base64-decoded payloads, `rm -rf ~/`, etc.). These
  signatures exist so the scanner can recognise attacker code. They are not
  themselves harmful.
- **Synthetic infection artefacts** generated at runtime inside a temporary
  directory by `python shai_hulud_guard.py --self-test`. The artefacts
  include a fake `gh-token-monitor` daemon, a fake malicious `postinstall`
  hook, and a fake `router_init.js`-style payload — used to verify that
  the scanner's detection logic still triggers correctly. The artefacts
  are written to a `tempfile.TemporaryDirectory()` and removed at the end
  of the test run. They never leave that sandbox and are never executed.
- **Indicator-of-compromise (IOC) data**: package names and version numbers
  that have been publicly disclosed as compromised. This information is
  already public (DataDog IOC repo, GitHub Advisory Database, CISA alerts).

Static-analysis tools, antivirus engines, and GitHub's push-protection
scanner may flag the source file because of the synthetic artefacts and
pattern signatures. **These flags are false positives in this context.**
A reviewer can confirm by reading `run_self_test()` and the
`MALICIOUS_PATTERNS` table directly.

## Supported versions

| Version | Supported |
|---|---|
| 2.4.x (current) | ✅ |
| 2.3.x | partial — bug fixes only |
| 2.0.x | ❌ archived in `legacy/`, not maintained |
| 1.1.x | ❌ archived in `legacy/`, not maintained |

## Reporting a vulnerability in this tool

If you find a way to **evade detection** (a known-compromised pattern that
`shai_hulud_guard --scan` fails to flag, or a calibration regression that
makes the scanner blind to a documented Shai-Hulud variant), please report
it **privately** before disclosing publicly. Public disclosure of an
evasion gives attackers a usable bypass before defenders can patch.

**Preferred channel:** open a private security advisory on the repository
under *Security → Advisories → New draft security advisory*.

**Email fallback:** *(insert maintainer contact here when the repo goes
public)*. Please include:

1. The package or version that the scanner failed to flag.
2. The expected detection (which check / pattern should have fired).
3. The output of `python shai_hulud_guard.py --check <pkg> --json` so we
   can reproduce the score deterministically.

We aim to acknowledge within **7 days** and to ship a fix within
**30 days** of confirmation. Reporters who follow this process are
credited in the relevant `CHANGELOG.md` entry.

## Reporting a *defect* (not an evasion)

If you find a non-security bug — crash, broken flag, wrong output, false
positive on a known-safe package — file it as a regular public GitHub
issue. False positives that block legitimate workflows are a documented
priority for this project: see `docs/DESIGN.md` § *calibration*.

## What this tool does *not* protect against

`shai_hulud_guard` is a pattern-and-IOC scanner. It does not:

- Sandbox or execute packages — a payload that obfuscates its strings well
  enough may pass the static scan and harm you on `npm install` regardless.
- Replace behavioural analysis services (Socket, Snyk, Wiz, Phylum).
- Replace a competent endpoint-protection / EDR product.
- Detect zero-day variants whose IOCs have not yet been published.

A non-zero risk score is a strong signal to investigate further; a zero
risk score is *not* a guarantee of safety. See `docs/DESIGN.md`
§ *limitations*.

## Disclosure timeline expectations

| Stage | Target |
|---|---|
| Acknowledgement of report | 7 days |
| Initial assessment | 14 days |
| Fix + advisory publication | 30 days |
| CVE/GHSA assignment (if applicable) | best-effort, via GitHub Advisory Database |

If a fix requires more than 30 days, we'll communicate the timeline and
the reasoning in the advisory thread.
