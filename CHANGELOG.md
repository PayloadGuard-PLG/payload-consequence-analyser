# Changelog

User-visible changes per release, newest first. Finding IDs (§V, §H) refer to [`AUDIT_LOG.md`](AUDIT_LOG.md); the engineering log is [`DEVLOG.md`](DEVLOG.md) (earlier history in [`docs/devlog/`](docs/devlog/)).

## Unreleased

### Changed
- **Branch age never decides DESTRUCTIVE (§H1).** Branch age is applied after every other signal. When those signals already total 5 or more it adds in full; otherwise it raises the score at most to 4, so age can lift a verdict to REVIEW or CAUTION but a DESTRUCTIVE verdict (exit code `2`) requires evidence from the change itself. A diff whose content scores CAUTION stays CAUTION on an old branch. The deceptive-description escalation (L5b) raises CAUTION to DESTRUCTIVE only when the content score alone reaches CAUTION. The verdict reports `branch_age_score`.
- **Escalated verdicts report matching severity, score and recommendation (§V12).** When a missing or contradicting PR description (L5b) or the consequence policy (`advisory`, `enforce`) raises the verdict, the severity, the recommendation and a score in the new verdict's band follow. The verdict reports the points added as `escalation_score`. Statuses and exit codes are unchanged.

### Fixed
- **Dormant workflow triggers are detected in any YAML layout (§H2).** The L2c check for a `workflow_dispatch` or `schedule` workflow that runs shell commands matched the trigger by line layout; `on: workflow_dispatch`, `on: [push, workflow_dispatch]`, a quoted `"on"` key and a trigger listed after another event went undetected. Triggers are now read from the parsed workflow.

## 1.6.0 — 2026-10-26

First release published to PyPI since 1.3.0. Fixes the defects found in an audit of 1.5.0 (§V1–§V11).

### Security
- `payloadguard.yml` and `allowlist.yml` are read from the target branch, not from the branch being scanned, so a pull request cannot change the policy its own scan runs under (§V1).
- The Action scans the pull request head commit instead of resolving the head branch name. Fork pull requests previously failed, or were compared against a same-named branch of the base repository (§V2).

### Added
- `consequence-mode` Action input (`shadow` | `advisory` | `enforce`). Precedence: `--consequence-mode` / the input, then `PAYLOADGUARD_CONSEQUENCE_MODE`, then `payloadguard.yml` (§V6).
- The Action's `verdict` output reports `REVIEW` and `CAUTION` (§V5).
- `.mjs`, `.cjs`, `.mts` and `.cts` files are parsed with the JavaScript and TypeScript grammars (§V7).
- `D01` reports changed source in languages without a structural parser as `UNSUPPORTED_EXTENSION` instead of reporting complete coverage (§V4).

### Fixed
- The distribution builds again; `consequence_engine` is included in the wheel (§V3).
- Non-finite branch age or target velocity raises `ValueError` instead of yielding a NaN drift score classified `CURRENT` (§V10).
- A console that cannot encode the report's symbols (redirected output on Windows) no longer turns the verdict into exit code `1` (§V11).

### Changed
- `requires-python` is `>=3.11` (was `>=3.8`, which could not import `structural_parser.py`).

## 1.5.0 — 2026-10-25

### Added
- `D08_WORKFLOW_INTEGRITY`: untrusted expression injection in `run:` blocks, `pull_request_target` with an untrusted checkout, action SHA pin downgrade, `continue-on-error` and `write-all` gate weakening, privileged `workflow_run` artifact use, and unpinned third-party actions (`actions/*` and `github/*` excluded).
- `D09_TEST_EROSION`: assertions replaced with tautologies and newly skipped tests.
- `D10_MIGRATION_PERSISTENCE_LOSS`: `TRUNCATE`, `DROP DATABASE` / `DROP SCHEMA`, multi-line SQL parsing, forward-versus-rollback isolation (Alembic, Knex/TypeORM/Sequelize, Rails, Goose/sql-migrate, Django) and framework-aware irreversibility.
- `D05` build wrapper tampering in `mvnw`, `gradlew`, `Makefile` and `build.sh`.

### Fixed
- `structural_parser.py` traverses nested function scopes when collecting constant booleans, removing false short-circuit findings for variables mutated through `nonlocal`.

## 1.4.0 — 2026-10-23

### Added
- Consequence Engine (`consequence.v1`): a Semantic Change Graph with five-stage symbol matching and detectors `D01`–`D06` (parser completeness, body weakening, compound loss, public API break, build and dependency delta, guard regression), with `shadow` (default), `advisory` and `enforce` modes (`--consequence-mode`).
- `SymbolFact` v1 extraction for Python (`ast`) and JavaScript, TypeScript, Go, Rust and Java (`tree-sitter`).
- Reporting: consequence section in the console report, collapsible evidence and remediation in the Markdown report, SARIF 2.1.0 output (`--save-sarif`).
- L2d AI tooling configuration poisoning: `.claude/settings.json`, `.gemini/settings.json`, `.cursor/rules/*.mdc`, `.vscode/tasks.json`, `package.json` lifecycle scripts, `composer.json`, `Gemfile`, `binding.gyp` and `mcp.json`. A CRITICAL signal scores 5, a HIGH signal 3.

### Changed
- Maximum score 31 → 36.

## 1.3.0 — 2026-05-31

### Fixed
- Multi-line `curl` commands with continuation lines are detected by the L2c credential-harvest check.

## 1.2.0 — 2026-05-25

### Added
- L2c GitHub Actions poisoning detection: base64 payloads, credential harvesting, dormant triggers, forged bot authors, OIDC elevation (including typosquatted consumers) and `pull_request_target` signals.
- L5b v2 semantic transparency engine (PR-MCI): linguistic lexer, diff profiler and cross-correlation, with an `mci_score` in [0, 1].
- L5c eBPF runtime agent: `execve`, `connect`, `ptrace` and process-memory tracepoints, audit and block modes, egress allowlist.
- L2 content scan of added non-code files for CI triggers and shell execution patterns (+2 per match, capped at +4).

### Fixed
- The L2 content scan no longer applies to `.github/workflows/` files; L2c handles them, so they are not scored twice.

## 1.1.0 — 2026-05-03

### Added
- L2b software composition analysis against `allowlist.yml` (opt-in).
- McCabe complexity advisory for newly added Python functions (no score impact).

### Fixed
- Cross-file structural aggregation requires both the count and the ratio threshold.
- YAML parse errors in `payloadguard.yml` print a warning instead of being ignored.
- The JavaScript and TypeScript parser tracks every `variable_declarator` name (`const`, `let`, `var`).
- Check Run summaries are truncated at a line boundary with open code fences closed; a missing `cryptography` package is reported at start-up.

## 1.0.0 – 1.0.2 — 2026-04-22 to 2026-04-23

Initial releases. See [`docs/devlog/`](docs/devlog/).
