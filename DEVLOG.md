# PayloadGuard — Developer Log

Reverse-chronological: most recent entry first. This log starts on 2026-10-27. Earlier history, from 2026-04-22 to 2026-10-27, is in [`docs/devlog/DEVLOG-2026-04-22_to_2026-10-27.md`](docs/devlog/DEVLOG-2026-04-22_to_2026-10-27.md) (closed).

## Conventions

- One entry per change set: date, title, and the [`AUDIT_LOG.md`](AUDIT_LOG.md) finding ID where one exists.
- State what changed, the evidence (harness results, test counts, proof runs) and what was not verified.
- Do not restate standing state in entries. The current version, open findings and test totals live in [`CLAUDE.md`](CLAUDE.md) (handover block), `AUDIT_LOG.md` and [`CHANGELOG.md`](CHANGELOG.md). User-visible changes also go in `CHANGELOG.md`.

## State at the start of this log (2026-10-27, `main` `0c3482c`)

- **Released:** v1.6.0 (2026-10-26, PyPI `payloadguard-plg` 1.6.0).
- **On `main`, not released:** §H1 (branch age never decides `DESTRUCTIVE`), §H2 (dormant triggers in any YAML layout), §V12 (escalated verdicts carry matching severity, score and recommendation). See `CHANGELOG.md`.
- **Open findings:** §2.3 (single-branch clone or detached HEAD raises `BadName`) and §V13 (the L5b report section prints its own "DO NOT MERGE" directive for every deceptive description, including when the verdict is `CAUTION`).
- **Harness:** the live regression workflow pins analyser commit `40b27dc`, which predates §V12; §V12 changes no status or exit code, so the harness results are unaffected.
- **Tests at the §V12 fix (`529014e`):** 418 passed with Z3 and CrossHair; 397 passed and 21 skipped without them. Harness oracle 41/41; mutation suite 16/16.

## 2026-10-27 — Documentation restructure: README by function, CHANGELOG, devlog split

**README:** rewritten around what the tool does: verdicts and scoring, analysis layers, detections, consequence engine, Action inputs and outputs, command line, configuration, reports, limitations, verification scope. Removed the per-release "What's New" sections, the "Unreleased" list and the hard-coded test and proof counts, which were out of date (the README stated 391 tests; the suite has 418). Added what the previous README omitted: the Action inputs `app-id`, `private-key`, `installation-id`, `auto-remediate` and `runtime-mode`, the `payloadguard.yml` defaults taken from `DEFAULT_CONFIG` (the example showed `max_repo_files: 500`; the default is 200), the scoring table, and the limitations. Corrected two statements: the Action does not write SARIF (`--save-sarif` is CLI only, so the `security-events: write` permission in the old example was unnecessary), and a command-line usage error exits `2`, the same code as `DESTRUCTIVE`. The verification section now states what the proofs cover (the signal-to-verdict mapping, on models) and what they do not.

**CHANGELOG.md:** new, from the README release notes and the version history in `CLAUDE.md`; dates from the release tags (1.0.0 to 1.6.0).

**Devlog:** the former `DEVLOG.md` (1,356 lines) moved with history to `docs/devlog/DEVLOG-2026-04-22_to_2026-10-27.md`, with a forward link in its header. This file is the continuation.

**Corrections found while checking the documents against the code:**
- AUDIT_LOG §INC-3 and the `CLAUDE.md` open-findings table listed it as open. It was fixed on 2026-05-25 (PR #42): `UNVERIFIED` raises `SAFE` to `REVIEW`, with tests in `test_analyzer.py`. Marked fixed.
- `SYSTEM_BLUEPRINT.md` summarised the test suite as 391 / 374 / 372 passed with 12 Z3 and 5 CrossHair skips; `PROOFS.md` and `VERIFICATION.md` expected "19 passed" from `tests/proofs/`. The current counts are 418 / 397 with 21 skipped, and 25 proof tests (18 Z3, 7 CrossHair). `TEST_REGISTRY.md` was regenerated.

**Not changed, for a decision:**
- `AGENTS.md` instructs agents to read `docs/research/` first and describes a "research branch" that "begins documentation-only". It is an instruction file, not documentation, and conflicts with how this repository is maintained now.
- `VERIFICATION_SPEC.md` §6 lists L4 and L5a as "not specified", while `VERIFICATION.md` lists CrossHair and Dafny contracts for both; the section reads as scoped to the L3 specification in that document.
- `controlled-2.json`, `part1.txt`, `orchestrator.py` and `trust_grader.py` sit in the repository root; `SYSTEM_BLUEPRINT.md` marks the last three as not part of the production path.

**Verification:** every link and code identifier in the changed documents resolves (`doc_checks`); README claims were checked against `action.yml`, `DEFAULT_CONFIG`, `_assess_consequence()`, `_apply_semantic_transparency()`, the CLI arguments and the report builders. No code changed.
