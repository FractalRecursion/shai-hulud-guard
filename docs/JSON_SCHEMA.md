# `--json` output schema

`shai_hulud_guard --json` emits a **single JSON object** to stdout when paired
with any read-only analysis mode. No banner, no ANSI colour, no per-step prose
— just one object suitable for piping into `jq`, downstream tools, or a
frontier LLM.

```bash
python shai_hulud_guard.py --json --scan        --path .
python shai_hulud_guard.py --json --check       lodash
python shai_hulud_guard.py --json --check-pypi  numpy
python shai_hulud_guard.py --json --lockcheck   --path .
python shai_hulud_guard.py --json --diagnose    --path .
```

Schema is **stable across all modes** that produce findings. Schema version is
declared in the `schema_version` field; bumps follow [semver](https://semver.org/).

---

## Top-level object

```json
{
  "schema_version":    "1.0",
  "tool":              { "name": "shai_hulud_guard", "version": "2.4.0" },
  "mode":              "check" | "check-pypi" | "scan" | "lockcheck" | "diagnose",
  "target":            "<package@version>" | "<absolute-project-path>",
  "risk_score":        0,
  "case":              "CLEAN" | "UNCERTAIN" | "LOW_CONFIDENCE" | "DAEMON_ONLY" | "PACKAGES_ONLY" | "FULL_COMPROMISE" | "LOCKFILE_TAMPERED",
  "confidence":        "DEFINITIVE" | "HIGH" | "MEDIUM" | "LOW" | "UNCERTAIN",
  "exit_code":         0,
  "findings":          [ /* Finding objects, see below */ ],
  "llm_instructions":  "<verbatim paste-into-LLM prompt fragment>"
}
```

### Field semantics

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | string | This document. Bump major when fields are removed/renamed. |
| `tool.name` | string | Always `"shai_hulud_guard"`. |
| `tool.version` | string | Tool version (matches `--version`). |
| `mode` | string | Which CLI flag drove this run. |
| `target` | string | What was analysed. For `--check`/`--check-pypi`: `package@version`. For others: absolute project path. |
| `risk_score` | int 0-100 | Aggregate risk. ≥40 = exit code 1; ≥70 = "do not install". |
| `case` | string | Classification — see `classify_infection()` in source. CLEAN is the only "safe" value. |
| `confidence` | string | How sure the tool is of its verdict. UNCERTAIN means "needs human review". |
| `exit_code` | 0 \| 1 | Mirrors the process exit code. Wrappers / CI use this to block installs. |
| `findings` | array | Zero or more Finding objects. May be empty even when risk_score > 0. |
| `llm_instructions` | string | Verbatim prompt fragment — paste together with the rest of the object into an LLM for analyst-grade guidance. |

### Finding object

```json
{
  "level":              "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
  "title":              "Short human-readable summary",
  "detail":             "Extended detail (path, snippet, justification)",
  "path":               "<file/package path>" | null,
  "score_contribution": 0,
  "advisories":         [ "GHSA-...", "CVE-..." ]
}
```

| Field | Type | Meaning |
|---|---|---|
| `level` | string | Severity. `CRITICAL` is a hard block; `INFO` is purely informational. |
| `title` | string | One-line description. |
| `detail` | string | Optional extended context. May be empty. |
| `path` | string \| null | File path inside a tarball, package name, or `null` when not path-bound. |
| `score_contribution` | int | Points this finding added to `risk_score`. 0 when not tracked. |
| `advisories` | array of string | GitHub Advisory Database (`GHSA-…`), NIST NVD (`CVE-…`), or OSV (`PYSEC-…`, `MAL-…`) IDs cross-referenced from `KNOWN_BAD`. Empty array does **not** mean "no public advisory exists" — it means "not cross-referenced yet". See [CHANGELOG.md § 2.4.0](../CHANGELOG.md). |

### Authoritative advisory sources

In priority order (see `CLAUDE.md § 4.7`):

1. **[GitHub Advisory Database (GHSA)](https://github.com/advisories)** — preferred for npm/PyPI ecosystem advisories.
2. **[NIST NVD](https://nvd.nist.gov/)** — when a CVE is issued for the underlying defect.
3. **[OSV](https://osv.dev/)** — unified aggregator (GHSA + others) with API.

---

## LLM workflow

The `llm_instructions` field is engineered so the entire JSON can be pasted
verbatim into a frontier LLM (Claude, GPT-4, Gemini) for analyst-grade
follow-up:

```bash
python shai_hulud_guard.py --json --scan --path . | pbcopy            # macOS
python shai_hulud_guard.py --json --scan --path . | clip               # Windows
python shai_hulud_guard.py --json --scan --path . | xclip -selection clipboard  # Linux
```

Paste into the LLM with a one-line preamble like:

> "Analyse this shai_hulud_guard output and advise."

The LLM will pick up the embedded `llm_instructions` and proceed.

---

## Worked examples

### 1. Clean package — `--check lodash`

```json
{
  "mode": "check",
  "target": "lodash@4.18.1",
  "risk_score": 0,
  "case": "CLEAN",
  "confidence": "DEFINITIVE",
  "exit_code": 0,
  "findings": [],
  "schema_version": "1.0",
  "tool": { "name": "shai_hulud_guard", "version": "2.4.0" },
  "llm_instructions": "..."
}
```

Exit code `0`. The wrapper script generated by `--protect` proceeds with the install.

### 2. Confirmed malicious — `--check intercom-client@7.0.4`

```json
{
  "mode": "check",
  "target": "intercom-client@7.0.4",
  "risk_score": 100,
  "case": "PACKAGES_ONLY",
  "confidence": "DEFINITIVE",
  "exit_code": 1,
  "findings": [
    {
      "level": "CRITICAL",
      "title": "CONFIRMED MALICIOUS: intercom-client@7.0.4",
      "detail": "Version pulled from npm registry. Campaign waves: Wave5-May2026",
      "path": "intercom-client@7.0.4",
      "score_contribution": 100,
      "advisories": []
    }
  ],
  "schema_version": "1.0",
  "tool": { "name": "shai_hulud_guard", "version": "2.4.0" },
  "llm_instructions": "..."
}
```

Exit code `1`. The wrapper script generated by `--protect` blocks the install
unless the user sets `SHAI_SKIP=1` to override.

### 3. Existing-project scan — `--scan --path .` (on a clean repo)

```json
{
  "mode": "scan",
  "target": "/home/user/myproject",
  "risk_score": 5,
  "case": "CLEAN",
  "confidence": "DEFINITIVE",
  "exit_code": 0,
  "findings": [],
  "schema_version": "1.0",
  "tool": { "name": "shai_hulud_guard", "version": "2.4.0" },
  "llm_instructions": "..."
}
```

`run_scan()` emits its findings inline during execution; the `findings` array
in `--json --scan` is therefore typically empty even when `risk_score > 0`.
Use `--diagnose` for a fully-structured per-finding rendering — that mode
returns each finding as a structured Finding object.

---

## CI integration recipe

```yaml
# .github/workflows/security.yml (excerpt)
- name: Pre-merge supply-chain check
  run: |
    python shai_hulud_guard.py --json --scan --path . > scan.json
    risk=$(jq -r '.risk_score' scan.json)
    case=$(jq -r '.case' scan.json)
    if [ "$risk" -ge 40 ]; then
      echo "::error::Supply-chain scan failed: risk=$risk case=$case"
      jq '.findings[] | select(.level == "CRITICAL" or .level == "HIGH")' scan.json
      exit 1
    fi
```

---

## Stability guarantees

- Field **names and types** are stable for all of `schema_version: 1.x`.
- New fields may be **added** in `1.x.y` patch / minor bumps. Consumers must
  ignore unknown fields, not reject them.
- Field **removals or type changes** require a major bump to `schema_version: 2.0`.
- The `llm_instructions` text content is **not stable** — it may be tuned
  between minor releases as we learn what works for downstream LLM analysis.
  Consumers that programmatically reason about its text should pin a version.

---

## Limitations

- `--scan` currently emits human-formatted findings inline and populates only
  the aggregate fields (`risk_score`, `case`, `confidence`) in JSON.
  Structured per-finding rendering for `--scan --json` is a planned
  enhancement for v2.5 — track in CHANGELOG.
- `--diagnose` emits its full report to a `.txt` file; the `--json` companion
  emits the same data structured. The `.txt` is for paste-to-LLM; the JSON
  is for programmatic consumers.
- Advisory cross-references in `KNOWN_BAD` are currently empty arrays
  (scaffolded). Population requires careful manual GHSA lookup per entry,
  deferred to a future minor — see `CHANGELOG.md § 2.4.0`.
