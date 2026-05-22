<!-- Thanks for contributing. This is a security tool — the checklist below is
     not ceremony; each item maps to an invariant that prevents real harm. -->

## What does this PR do?



## Related issue


## Type of change
- [ ] Bug fix
- [ ] New IOC / signature (cited source required — see below)
- [ ] New feature / mode
- [ ] Docs / infra only

## Checklist
- [ ] `python -m ruff check .` passes (no new findings)
- [ ] `python -m pytest` passes (and I added/updated tests)
- [ ] `python shai_hulud_guard.py --self-test` passes (6/6)
- [ ] No runtime dependency added (stdlib only — CLAUDE.md §5.4 / §7)
- [ ] No target code is executed; tarballs/wheels read in memory only (§5.1)
- [ ] No credential contents read; nothing phones home (§5.3 / §5.4)

## If this PR adds an IOC / regex (CLAUDE.md §4.7, §5.5)
- [ ] Cited an authoritative public source (GHSA / NVD / OSV / Datadog / CISA / Wiz / StepSecurity) in a comment above the entry
- [ ] Added a matching exemplar to `tests/test_patterns.py::EXEMPLARS`
- [ ] Ran `benchmarks/run_calibration.py` — false-positive set stays within thresholds, true-positive set stays CRITICAL
