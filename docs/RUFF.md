# Ruff — what it is, why we use it, how it works

This document is for someone who has not used `ruff` before and wants to understand exactly what it does on this project, what each rule group catches, and how to run it day-to-day.

---

## 1. What is `ruff`?

`ruff` is a **single tool that replaces several older Python tools at once**:

| Old tool                  | What it did                          | Replaced by ruff |
|---------------------------|--------------------------------------|------------------|
| `flake8`                  | Style + lint (errors / warnings)     | ✅ |
| `pycodestyle`             | PEP 8 style checks                   | ✅ |
| `pyflakes`                | Real bugs (unused imports, etc.)     | ✅ |
| `isort`                   | Import sorting                       | ✅ |
| `pyupgrade`               | Modernise old-style Python syntax    | ✅ |
| `bandit`                  | Security lint                        | ✅ (subset) |
| `flake8-bugbear`          | Catch common Python footguns         | ✅ |
| `black` (formatter)       | Auto-format code                     | ✅ (`ruff format`) |

It is written in Rust, which is the relevant practical fact: it runs **10–100× faster** than the tools it replaces. A full check on this project finishes in well under a second.

### Why we picked it for this project (in particular)

1. **One dev dependency instead of five.** This project is itself a supply-chain-hardening tool. The fewer dev dependencies we pull in, the smaller our own supply-chain risk.
2. **`bandit`-style security rules are built in.** For a security tool, automated checks for `shell=True`, hardcoded secrets, unsafe deserialisation, and similar primitives are non-optional.
3. **Speed.** A lint run that finishes in <1 second is one you actually run before every commit, instead of letting it become a CI-only afterthought.

---

## 2. How it works (mental model)

`ruff` walks every `.py` file under the project root, parses each one into an AST, and applies two distinct kinds of operation:

```
                      ┌──────────────────────────────┐
   ruff check    ───► │ Lint rules — find problems   │ ──► report (+ optional --fix)
                      └──────────────────────────────┘
                      ┌──────────────────────────────┐
   ruff format   ───► │ Formatter — rewrite layout   │ ──► files rewritten
                      └──────────────────────────────┘
```

- `ruff check` reports issues. With `--fix`, it auto-fixes the ones it can safely rewrite.
- `ruff format` rewrites whitespace, quoting, and line breaks. It does **not** change semantics; it is the equivalent of `black`.

Both subcommands read configuration from `pyproject.toml` under `[tool.ruff]`, `[tool.ruff.lint]`, and `[tool.ruff.format]`.

---

## 3. The configuration in this project (in plain English)

Our config lives in `pyproject.toml`. Annotated here:

```toml
[tool.ruff]
line-length = 120
target-version = "py38"
```

- **`line-length = 120`** — we allow longer lines than `black`'s default 88. The IOC pattern tables in `shai_hulud_guard.py` are intentionally formatted as `(regex, description, risk)` triples per line; breaking those across multiple lines hurts readability more than it helps.
- **`target-version = "py38"`** — the lower bound of Python versions we support. `ruff` uses this to decide whether a `pyupgrade` rule is safe (e.g., it won't suggest `int | str` syntax because that requires 3.10+).

```toml
[tool.ruff.lint]
select = ["E", "F", "W", "I", "B", "UP", "S", "C4", "SIM", "RET"]
```

These are **rule groups**, each identified by a letter prefix. What each one does:

| Code | Group                   | What it catches | Example |
|------|-------------------------|-----------------|---------|
| `E`  | pycodestyle errors      | PEP 8 errors    | `E711` — `if x == None:` (should be `is None`) |
| `W`  | pycodestyle warnings    | PEP 8 warnings  | `W605` — invalid escape sequence in string literal |
| `F`  | pyflakes                | **Real bugs**   | `F401` unused import, `F821` undefined name, `F841` unused local variable |
| `I`  | isort                   | Import order    | Standard library first, third-party second, local last — alphabetised within groups |
| `B`  | flake8-bugbear          | Python footguns | `B006` mutable default arg, `B007` unused loop var, `B008` function-call default arg |
| `UP` | pyupgrade               | Modernise syntax | `UP006` use `list` instead of `List` from typing (where target-version allows) |
| `S`  | flake8-bandit           | **Security**    | `S101` assert, `S102` exec, `S301` pickle, `S605` shell, `S608` SQL injection |
| `C4` | flake8-comprehensions   | Idiomatic comprehensions | `C401` unnecessary generator → set literal |
| `SIM`| flake8-simplify         | Obviously simplifiable code | `SIM101` use `isinstance(x, (a, b))` not `or` |
| `RET`| flake8-return           | `return` consistency | `RET504` unnecessary assignment before return |

The `S` (security / bandit) group is the most important for this project — it catches the kind of mistake that, in a security tool, would be embarrassing at best and dangerous at worst.

### What we deliberately ignore

```toml
ignore = ["S603", "S607", "E501"]
```

- **`S603`** — "`subprocess` call without `shell=True` check". The rule is too coarse: it flags every `subprocess.run([...])`, even though we already follow the actual safe-pattern (list-arg form, never `shell=True`) project-wide.
- **`S607`** — "starting a process with a partial executable path". We intentionally call `npm`, `git`, `node` by name so the OS PATH resolves the user's installed version. Hardcoding `/usr/bin/npm` would be wrong on macOS Homebrew, on Windows, and on any non-default Linux install.
- **`E501`** — "line too long". `line-length = 120` already gives us room; the IOC pattern table needs the rest.

### Per-file overrides

```toml
[tool.ruff.lint.per-file-ignores]
"tests/**/*.py" = ["S101", "S105", "S106", "S404", "S301", "B011"]
"build.py"      = ["S404"]
```

Test files legitimately use `assert` (`S101`), construct fixture strings shaped like tokens (`S105/S106`), import `subprocess` to mock it (`S404`), and may construct synthetic pickle bytes (`S301`). Forbidding those would make the tests unwriteable. The build script also legitimately uses `subprocess`.

### Format settings

```toml
[tool.ruff.format]
quote-style = "double"
indent-style = "space"
```

Match the existing style in `shai_hulud_guard.py` and `shai_hulud_guard V2.0.py`.

---

## 4. Day-to-day usage

### Install (once)

```bash
# In a virtualenv at the project root:
python -m venv .venv
# Activate: source .venv/bin/activate  (Linux/macOS)
#           .\.venv\Scripts\Activate.ps1  (Windows PowerShell)
pip install -e ".[dev]"
```

`-e ".[dev]"` installs this project in editable mode with the optional `dev` dependency group (which includes ruff, pytest, pyinstaller).

### The two commands you will actually run

```bash
ruff check .                  # report issues
ruff check . --fix            # report + auto-fix the safely-fixable ones
ruff format .                 # rewrite whitespace / quoting (no semantic changes)
ruff format . --check         # check formatting without rewriting (CI mode)
```

Before committing, you want **all four exit codes to be zero**:

```bash
ruff check . && ruff format . --check
```

This is also the command CI will run (see `.github/workflows/ci.yml` once that exists — currently TODO).

### Useful narrower commands

```bash
ruff check shai_hulud_guard.py            # one file
ruff check . --select S                   # only security rules
ruff check . --statistics                 # count violations per rule
ruff check . --show-fixes                 # preview what --fix would do
ruff rule S101                            # explain a specific rule
```

### What `--fix` will and won't do

`ruff` distinguishes **safe** and **unsafe** auto-fixes.

- **Safe**: `--fix` applies them. Example — removing an unused import, sorting imports, replacing `dict()` with `{}`.
- **Unsafe**: you need `--fix --unsafe-fixes` to apply them. Example — converting `typing.List` to `list` is an *unsafe* fix because if anything reflects on annotations at runtime, the semantics change.

Default to plain `--fix` unless you have read the diff.

### Disabling a rule on a single line

```python
result = subprocess.run(cmd, check=False)  # noqa: S603
```

Use this sparingly. If you find yourself adding `# noqa` more than once or twice in the project, the rule probably belongs in `ignore = [...]` in `pyproject.toml` with a comment explaining why.

---

## 5. How this interacts with the rest of the project

- **Pre-commit.** No `pre-commit` framework is configured yet. When it is (TODO §8.4 in `CLAUDE.md`), it should run `ruff check . --fix` and `ruff format .` on staged files.
- **CI.** When `.github/workflows/ci.yml` is added (also TODO §8.4), it should run `ruff check .` and `ruff format . --check` on every PR. CI uses `--check` mode for the formatter so that a PR that hasn't been formatted fails fast, instead of silently rewriting code in the runner.
- **Editor integration.** Ruff has first-class extensions for VS Code (`charliermarsh.ruff`) and JetBrains IDEs. Pointed at the project root, they read the same `pyproject.toml` and surface violations inline.

---

## 6. What ruff is *not*

- **Not a type checker.** It does not understand types. For type checking use `mypy` or `pyright` — but neither is currently in the dev deps for this project and there is no plan to add one for a stdlib-only script.
- **Not a test runner.** That's `pytest` (see the `tests/` directory).
- **Not a vulnerability scanner.** The `S` (bandit) rules are *static* — they catch code patterns, not known-CVE dependencies. For dependency vulnerability scanning you would use a separate tool like `pip-audit`. The project has no runtime dependencies so this is moot in our case, but worth knowing.
- **Not a substitute for `CLAUDE.md` invariants.** Ruff catches `subprocess(shell=True)`. It does **not** catch "you accidentally added a feature that auto-revokes a GitHub token". The project's safety invariants (see `CLAUDE.md` §5) need code review, not lint.

---

## 7. Adding or changing rules in the future

Edit `[tool.ruff.lint]` in `pyproject.toml`. The pattern is:

```toml
select = [..., "NEW_GROUP_PREFIX"]   # turn on
ignore = [..., "SPECIFIC_RULE_CODE"] # turn off specific rules from the selected groups
```

The full list of rule groups and codes lives at <https://docs.astral.sh/ruff/rules/>. If you turn on a new group, run `ruff check .` once and decide whether to fix the resulting violations or add the noisy ones to `ignore`. **Document the reasoning in a comment above `ignore = [...]`** — silent ignores are forgotten quickly and become invisible style drift.

If you ever need to know what a code means without leaving the terminal:

```bash
ruff rule B006
# → flake8-bugbear: Do not use mutable data structures for argument defaults.
#   Argument defaults are evaluated once at function definition time. ...
```
