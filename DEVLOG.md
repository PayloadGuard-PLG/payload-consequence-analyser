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

## 2026-10-29 — Round-3 adversarial evaluation fixes (branch `fix/round3-audit`)

Source: `ROUND3_REPORT.md` (external evaluation of `main` `ce44e3e`). Findings, severities and commits are in the AUDIT_LOG register "Adversarial Evaluation Round 3"; this entry records method and evidence. Fixed in order of consequence, one commit per group:

1. `fe32395` MOVE-01: renames and copies into config, workflow, build and migration paths are analysed (L2c, L2d, SCA, D05, D08, D10).
2. `1518386` FP-01 (first-round report, still open) and BUILD-07: hidden-Unicode class written with escapes; `package.json` SCA parsed as JSON.
3. `c08d98b` SEM-01/04: L5b profiles a patch diff.
4. `e4b3848` TYPE01, BUILD-01, BUILD-04, BUILD-11: symlinked sources read through their target; active build lines compared as whole lines; automatic npm hooks; malformed JSON shapes in L2d.
5. `e08571c` SEC01/03/06/12/14/19 and SEC10: Python execution facts and the D06 rules that use them; helper delegation.
6. `8553f04` IDX-02, CTX01, DUP01, ENC01: reference-first caller index and coverage reporting; D01 side grouping; source decoding.

**Evidence.**
- Campaign replay: every case's recorded base and head commits run through the analyser before and after, in all three modes. Each reported finding changes as intended; every control in the report keeps its verdict.
- Harness: oracle 41/41; mutation suite 16/16 (0 FP / 0 FN); the 38 fixtures replayed offline in shadow mode with their live PR bodies show no verdict or exit-code change.
- Real history in enforce mode (frozen `main` vs the branch, parent → commit, commit subject as description): this repository (74 code commits), the harness (20), and The-Node (200, mostly TypeScript). Used to calibrate the new rules:
  - The first `GUARD_CONDITION_WEAKENED` flagged an argparse rewrite in this repository (`9faa412`) that removed a deny branch; the rule was narrowed to deny conditions on identical terms.
  - Helper delegation initially left a 25-label D06 finding on The-Node `d237eff`, where 2 validators and 20 state-guard clauses moved two calls deep into a helper; extending delegation to identical clauses reduced it to the one clause the commit relaxed.
  - Remaining differences: FP-01 removes a false CAUTION from 33 of The-Node's 200 commits; L5b raises 9 of 74 and 15 of 200 (all exit 0; SEM-02 below); DUP01 moves 6 The-Node commits that touch two files Tree-sitter cannot parse from D01 WARN to REVIEW; D04 findings state the caller-index coverage. No new BLOCK.
- Tests: 504 passed with Z3/CrossHair; 483 passed, 21 skipped without (`test_analyzer.py` 341, `test_consequence_engine.py` 138). Each group's new tests were run against the unfixed source and failed there, except the controls.

**Open, for a decision:**
- SEM-02: with real patch text, V_r (`phantom_additions`) fires on add-heavy "fix" PRs with no churn floor, and the micro-scope lexicon matches domain words ("grammar", "cleanup"). Calibrating L5b changes the modelled behaviour in `verification/semantic_pure.py` (M1–M9).
- The six SEC rules use execution facts produced by the Python frontend only; TypeScript and other languages get helper delegation but not the new checks.
- Not in the reported priorities and not addressed: SEC17, SEC22, BOOK01, TF01, and the first- and second-round findings other than FP-01 (SCA-03, compact JSON, is resolved by the BUILD-07 change).

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
