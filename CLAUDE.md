# PayloadGuard — Claude Code Context

## Handover (update this block at the end of every session)

- **Branch state:** `main` at `6c3df91` = **v1.6.0, released**: tag `v1.6.0` on the PR #110 merge commit (tree identical to the verified tree `f4477970…`; #110 checks passed); "Publish to PyPI" run 40350394223 succeeded; `pip install payloadguard-plg==1.6.0` from PyPI verified in a fresh virtualenv. PR #108 was closed without merging (no-op). The six fix/docs branches of this work are deleted. §V8 merged via PR #111 (`28345bc`); its branch is deleted. Documentation pass merged via PR #112 (`19215fd`). Active: `docs/harness-history-aging` (this handover entry and AUDIT_LOG §H1–§H3); not merged.
- **Harness scan history + live regression attempt (2026-10-26, branch `docs/harness-history-aging`; harness branch `data/scan-history`):**
  - Harness `tools/collect_history.py` records every `PayloadGuard` check run on the fixture PRs' head commits in harness `regression-reports/scan_history.jsonl`; artifacts expire after 90 days, check runs do not. Collected 423 scans (2026-04-24 to 2026-05-31, 17 sweeps). The last sweep (2026-05-31, `fe68338`) matches 34/34 exit codes and 33/34 verdicts against the current manifest.
  - Live regression run #27 failed before reopening any PR: `REGRESSION_PAT` returns 401 (§H3). The sweep was run instead by reopening and closing the 34 fixture PRs from the browser (no merges): v1.6.0 live 34/34 exit codes, 27/34 verdicts (the seven mismatches are age-only SAFE→REVIEW). History: 457 scans, 18 sweeps.
  - Offline preflight against harness `main` `defb060` with v1.6.0: 38/38 exit codes match; 14 verdicts are raised by branch age alone. §H1: the six CAUTION-expected stable cases become DESTRUCTIVE for age once harness `main` has a commit dated from 2026-11-22. §H2: RTA01's REVIEW expectation relies on a content-scan signal removed in v1.2.0.
  - No analyser code changed. Tests: `test_analyzer.py` 311 passed.
- **§V8 Z3 P9 repair (2026-10-26, branch `fix/z3-p9-score-bound`):**
  - §V8 fixed (`4da89c4`): P9 asserted its bound as a constraint and checked the negation, so it passed for any bound (0, −100). It now builds the score from `_assess_consequence()`'s per-signal contributions and proves score ≤ 36; companion tests show 36 is reachable, that dropping the content-flag cap breaks the bound, and that the production scorer with every signal maxed returns 36. A bound of 35 yields a counterexample.
  - **Tests:** 391 passed with Z3/CrossHair (`tests/proofs/` 19); 374 passed, 17 skipped without them.
- **Version history + proof runs + §V10 (2026-10-26, branch `docs/v1.5.0-version-history-and-proofs`):**
  - Docs brought to v1.5.0 (CLAUDE.md current version and changelog incl. "Unreleased" §V1–§V7; SYSTEM_BLUEPRINT, WHITEPAPER, llms.txt, VERIFICATION, PROOFS). Stale proof records corrected (Z3 table vs actual P1–P10; C-03 bound 36; proof-suite counts).
  - Proof runs: Z3 P1–P10 10/10 and CrossHair wrappers 5/5 (`tests/proofs/`, z3-solver 5.3.2.0, crosshair-tool 0.0.112, local Windows/Python 3.14). Full CrossHair CLI (`--per_condition_timeout 30`): `consequence_pure`, `structural_pure`, `semantic_pure` 0 counterexamples; `temporal_pure` counterexample → §V10. Dafny run #16 (GitHub Actions, `9e83cce`): 7 + 1 + 1 verified, 0 errors — first recorded verification of the Sprint 1 `assess_consequence.dfy` (§V9 fixed).
  - §V10 fixed (`c74f612`): `TemporalDriftAnalyzer.analyze_drift()` accepted ∞/NaN velocity (0 × ∞ = NaN → CURRENT); now raises `ValueError` for non-finite age or velocity, and `temporal_pure.py` adds `pre: math.isfinite(target_velocity)`. CrossHair retest exits 0.
  - §V8 fixed later on `fix/z3-p9-score-bound` (see above).
  - **Tests:** 387 passed with Z3/CrossHair installed (368 + 15 proof + 4 §V10); 372 passed, 15 skipped without them.
- **§V5–§V7 Action outputs, consequence-mode input, JS/TS module extensions (2026-10-26, branch `fix/v5-v7`):**
  - §V5 fixed (`3780691`): the action's `verdict` output mapped exit 0 to SAFE; it is now read from the JSON report (exit-code mapping as fallback), so REVIEW and CAUTION are emitted.
  - §V6 fixed (`3780691`): new `consequence-mode` input (validated in the step; invalid values exit 1 rather than argparse's 2, which would read as DESTRUCTIVE). `PAYLOADGUARD_CONSEQUENCE_MODE` moved from `analyze()` to `main()`: `--consequence-mode` > environment > `payloadguard.yml`. README enforce example corrected.
  - §V7 fixed (`81d9481`): `.mjs`/`.cjs` → `javascript`, `.mts`/`.cts` → `typescript` in `_EXT_TO_LANG`, removed from `_UNPARSED_SOURCE_EXTS`. Legacy L4 now covers these files as it covers `.js`/`.ts`; calibrated by parity tests. No harness fixture contains these extensions.
  - **Tests:** 368 passed, 15 skipped (Z3/CrossHair not installed). Harness oracle 41/41; mutation suite 16/16; six-scenario Action simulation unchanged. All AUDIT_LOG 2026-10-26 findings (§V1–§V7) are fixed.
- **§V4 D01 unsupported-language coverage (2026-10-26, branch `fix/d01-unsupported-extension`):**
  - §V4 fixed (`cdb8395`): `ConsequenceEngine.analyze_deltas()` skipped files without a registered parser, so D01 never emitted `UNSUPPORTED_EXTENSION` and a Ruby/C#/`.mjs` change reported `parser_completeness.complete: true`. Source files listed in `_UNPARSED_SOURCE_EXTS` now reach `extract_symbols()`; D01 reports them as LOW / WARN with a manual-review remediation; syntax capability is `unavailable` when no changed file had a parser. Data/config/markup files remain excluded; SQL migrations remain with D10. Verdicts and exit codes are unchanged.
  - New open finding §V7 (LOW): `.mjs`/`.cjs`/`.mts`/`.cts` are not mapped to the installed JS/TS grammars.
  - **Tests:** 354 passed, 15 skipped (Z3/CrossHair not installed). Harness oracle 41/41; mutation suite 16/16.
- **§V3 distribution packaging repair (2026-10-26, branch `fix/pyproject-packaging`):**
  - §V3 fixed (`6b66374`): `pyproject.toml` listed `consequence_engine` under `packages`; it is a single-file module, so `pip install .` and `python -m build` (publish.yml) failed. It is now in `py-modules`. Removing the `packages` line alone builds a wheel without `consequence_engine.py`, which `analyze.py` imports at load time.
  - `TestDistributionPackaging` builds sdist → wheel as publish.yml does and runs a scan through the installed `payloadguard` entry point. Verified separately: `pip install` into a fresh venv; the `payloadguard` console script returns exit 2 on a gutted method and exit 0 on a benign change.
  - **Tests:** 347 passed, 15 skipped (Z3/CrossHair not installed). Harness oracle 41/41; mutation suite 16/16.
- **§V2 fork-PR head resolution repair (2026-10-26, branch `fix/action-pr-head-sha`):**
  - §V2 fixed (`0e7e68a`): `action.yml` and `.github/workflows/payloadguard.yml` passed `github.head_ref`, so fork PRs exited 1 ("Branch not found") or, when the fork branch name existed in the base repository (`main`), scanned that branch: base diffed against itself → SAFE. The scan step now passes `github.event.pull_request.head.sha` with `github.head_ref` as the fallback. Reports name the scanned commit SHA in `analysis.branch`.
  - **Tests:** 344 passed, 15 skipped (Z3/CrossHair not installed), 0 xfailed. Harness oracle 41/41; mutation suite 16/16. Live PR harness not run.
- **v1.5.0 audit + §V1 policy trust-boundary repair (2026-10-26, branch `fix/policy-from-target-branch`):**
  - Findings §V1–§V6 recorded in `AUDIT_LOG.md` (Findings Register — Audit Run: 2026-10-26).
  - §V1 fixed (`6d1477e`): `payloadguard.yml` and `allowlist.yml` were read from the working tree, which in CI is the PR merge result, so a PR could set `consequence.mode: shadow`, raise thresholds or allowlist its own dependency and pass its own scan. `load_config(repo_path, ref=None)` and `_load_allowlist(repo_path, ref=None)` now read from `ref` via `_read_file_at_ref()` (origin/<ref> fallback); `main()` passes the target branch and `analyze()` the resolved target. Without `ref` the working-tree behaviour is unchanged.
  - §V5/§V6 fixed on `fix/v5-v7` (see above).
  - **Tests:** 340 passed, 15 skipped (Z3/CrossHair not installed), 1 xfailed (§V2 evidence) across `test_analyzer.py`, `test_consequence_engine.py`, `tests/`. Harness `validate_manifest.py --verify-consequence` 41/41; mutation suite 16/16 (0 FP / 0 FN). Live PR harness not run.
- **D10 Migration/Persistence Loss + D05/D08 Extensions (Robust Real-Diff Hardening) — COMPLETE (2026-10-25, branch eat/d08-d09-d10-consequence-detectors):**
  - consequence_engine.py: Hardened D10_MIGRATION_PERSISTENCE_LOSS with multi-statement SQL AST/tokenizer parser, forward-vs-rollback boundary isolation, and framework-aware irreversibility:
    - Multi-line statement parsing for SQL migrations (handling comments, quoted identifiers, and ALTER TABLE ... DROP [COLUMN]).
    - Multi-language forward-vs-rollback isolation across Alembic (upgrade() vs downgrade()), Knex/TypeORM/Sequelize (up() vs down()), Rails (change vs up/down), and Goose/sql-migrate (-- +goose Up vs -- +goose Down, paired *.up.sql/*.down.sql). Legitimate drops inside rollback code/sections are excluded (0 false-positives).
    - Framework-specific irreversibility detection: Rails change drops without blocks, Django RunSQL without 
everse_sql, empty/missing downgrade() or down() functions, or missing/empty rollback scripts flag IRREVERSIBLE_PERSISTENCE_DROP (BLOCK); reversible drops flag DESTRUCTIVE_PERSISTENCE_MIGRATION (REVIEW).
    - Hardened migration directory detection excluding seed/, ixtures/, doc/, sample/, and vendor/test paths.
  - D08_WORKFLOW_INTEGRITY: Refined _WORKFLOW_RUN_TRIGGER_RE to match actual workflow triggers (on: workflow_run) rather than shell string expressions; excluded first-party GitHub-owned action namespaces (ctions/*, github/*) from ACTION_PIN_UNPINNED to focus exclusively on third-party supply chain risks.
  - D05_BUILD_DEPENDENCY_DELTA: BUILD_WRAPPER_TAMPERING (BLOCK) for new remote-exec/reverse-shell lines in mvnw, gradlew, Makefile, uild.sh.
  - **Tests:** 330 passed (284 	est_analyzer.py + 46 	est_consequence_engine.py); harness mutation suite 16/16 (0 FP / 0 FN); alidate_manifest.py --verify-consequence 41/41.
- **Consequence Engine v1 (`consequence.v1`) + Detector Accuracy & Usability v2 + D08/D09 Differential Workflow & Test Integrity — COMPLETE (2026-10-24):**
  - `structural_parser.py`: Upgraded with `SymbolFact` v1 (including `guard_conditions`), `CallSiteFact`, `ParseResult`, 7-dimension capability vectors (`universal`, `syntax`, `symbolic`, `typed`, `reachability`, `flow`, `runtime`), import-alias extraction (`as` bindings and CommonJS `require`), intra-function guard condition & test contract extraction (`_python_extract_guard_conditions`, `_ts_extract_guard_conditions` — including boolean short-circuit `if_short_circuit:`, Python/Go/JS state guards `if_state_guard:`, test assertion counts `test_assertions:<eff>:<triv>`, and skip calls `test_skip_call:true`), and explicit parser completeness (`AVAILABLE`, `PARSE_ERROR`, `GRAMMAR_UNAVAILABLE`, `UNSUPPORTED_EXTENSION`, `TIMEOUT`) across `.py`, `.js`/`.jsx`, `.ts`/`.tsx`, `.go`, `.rs`, and `.java`. Legacy `extract_named_nodes(source, path) -> set[str]` preserved 100% unchanged.
  - `consequence_engine.py`: Semantic Change Graph (SCG) 5-stage symbol matching pipeline + 8 deterministic consequence detectors (`D01_PARSER_INCOMPLETE`, `D02_BODY_WEAKENING` / `D02_AMBIGUOUS_REFACTOR`, `D03_COMPOUND_LOSS`, `D04_PUBLIC_API_BREAK` v2 with import-alias/module disambiguation and container/file consolidation, `D05_BUILD_DEPENDENCY_DELTA`, `D06_GUARD_REGRESSION` v2 with guard condition polarity inversion, enforcement neutralization, boolean short-circuiting `and False`/`|| true`, Python/Go/JS state-guard removal, unconditional early-return bypass, and exception-swallowing detection, `D08_WORKFLOW_INTEGRITY` differential CI/workflow detector for `run:` expression injection, `pull_request_target` untrusted checkout, SHA pin downgrade, and `continue-on-error: true` gate weakening, and `D09_TEST_EROSION` for tautological assertion replacement and newly skipped tests).
  - `analyze.py`: Integrated `consequence_analysis` report section (`consequence.v1`) with configurable policy mode (`shadow` default, `advisory`, `enforce` via `payloadguard.yml` or `--consequence-mode`), CLI `print_report()` consequence output, collapsible `<details><summary>Evidence & Remediation</summary>` drill-down in `format_markdown_report()`, and SARIF 2.1.0 output (`format_sarif_report()`, `save_sarif_report()`, `--save-sarif`).
  - **A03, A06, Mutation Suite & Multi-Language Payload Validation**: Both previously bypassing adversarial cases (`adversarial/slow-deletion` and `adversarial/threshold-gaming`), 16/16 adversarial and benign mutations in `run_mutation_suite.py` (0 FPs, 0 FNs), and all 41 test harness manifest cases (`validate_manifest.py --verify-consequence`) pass deterministically.
  - **Test suite:** `320 passed in 2.79s` (`284` in `test_analyzer.py` + `36` in `test_consequence_engine.py`).
- **Previous Sprint 1 — COMPLETE (2026-06-11, SHA 257d1f3):**
  - L2d AI tooling config poisoning detection shipped: `_scan_ai_tooling_configs()` + 8 helper functions.
  - Confirmed Miasma surfaces covered: `.claude/settings.json`, `.gemini/settings.json`, `.cursor/rules/*.mdc`, `.vscode/tasks.json`, `package.json` lifecycle scripts, `composer.json` post-install-cmd, `Gemfile` system(), `binding.gyp` shell chain, `mcp.json`.
  - `_assess_consequence`: `ai_config_poisoning_flags` / `ai_config_poisoning_critical` params added. CRITICAL +5 → DESTRUCTIVE floor, HIGH +3 → CAUTION.
  - MAX_SCORE: 31 → 36.
  - `verification/consequence_pure.py`: `_MAX_SCORE` 31→36, POST-12 contract added.
  - `verification/dafny/assess_consequence.dfy`: `MAX_SCORE` 31→36, POST-12 postcondition added.
  - `tests/proofs/test_z3_properties.py`: `_MAX_OTHER_SCORE` 19→24.
  - 16 new tests in `TestAIToolingConfigPoisoning` (8 unit, 8 integration; 3 FP-anchor safe cases).
  - Test suite: **274 pass, 0 fail** (`test_analyzer.py` alone; Z3/CrossHair require external install).
- **Next:** Replace the harness `REGRESSION_PAT` (§H3) so `regression.yml` can run again; after each live sweep run `collect_history.py` and commit `regression-reports/`. Decide whether D08 on AW04 (SAFE-expected) should block in enforce mode. Decide §H1 before 2026-11-22 and §H2. Then Sprint 2 (L1-ext: executable magic bytes + compound large-blob detector) and Sprint 3 (harness WS08/WS09/WS10).
- **CI:** `trigger-regression.yml` manual-only (`workflow_dispatch`). Harness `regression.yml` also manual-only.
- **Harness regression — last verified 2026-06-01 (analyser SHA fe68338, v1.3.0) — 34/34 PASS.**
  - Sprint 1 adds a new detection layer; re-regression required after merge to confirm no regressions on existing 34 cases.

- **Regression verification — 2026-06-01 (analyser SHA fe68338, v1.3.0) — COMPLETE 34/34:**
  - PASS (34/34): T03, T04, T05, T09, T10, T11, A01, A02, A03, A04, A05, A06, A07, A09, WS01–WS07, AW01–AW05, RTA01–RTA05, RT01–RT03
  - FAIL: none

- **A03/A06 (resolved 2026-06-01):** Both are documented bypass cases — SAFE is correct. A03: cross-file structural ratio ~8% < 20% threshold. A06: all metrics sub-threshold, no compound detection rule. Were returning DESTRUCTIVE only while PLI was active. Expectations corrected in harness test_cases.json and HARNESS.md (PR #72).

- **Branch inventory (as of 2026-06-11):**
  - Analyser: `main`, `release/v1.2.0`, `DarkVader-PLG-vericode` (R&D — keep), `claude/oidc-typosquat-detection-UBCOJ`, `claude/general-conversation-klxctt` (active — Sprint 1)
  - Harness: `main`, `claude/oidc-typosquat-detection-UBCOJ`, `test/megalodon-simulation`, `claude/general-conversation-klxctt`, all 38 permanent fixture branches
- **Vericoding Phase 4 — Dafny (PR #70, main `b44a116`):**
  - `verification/dafny/assess_consequence.dfy`: L3 — POST-1–11a + POST-12 (ai_config_poisoning_critical → DESTRUCTIVE, added Sprint 1). MAX_SCORE updated 31→36.
  - `verification/dafny/structural_drift.dfy`: L4 — S1–S7 dual-gate biconditional
  - `verification/dafny/temporal_drift.dfy`: L5a — T1–T8 linear drift, zero-input guarantees
  - `.github/workflows/verify-dafny.yml`: CI — Dafny 4.9.1; runs on PR/push touching `verification/dafny/**`
  - `verify-dafny.log` placeholder in place — replace with actual `dafny verify` output after local run
- **Vericoding Phase 2 — CrossHair (all 4 layers verified):**
  - `verification/consequence_pure.py`: Layer 3 — C1–C12 contracts + POST-12 implication. `_MAX_SCORE` updated 31→36 (Sprint 1). `_no_signals` and `assess_consequence_pure` updated with new params.
  - `verification/temporal_pure.py`: Layer 5a — T1–T7
  - `verification/structural_pure.py`: Layer 4 — S1–S7
  - `verification/semantic_pure.py`: Layer 5b — M1–M9
  - `tests/proofs/test_crosshair_contracts.py`: 5 pytest tests (`@pytest.mark.crosshair`)
  - Run CrossHair: `cd verification && crosshair check <module> --analysis_kind PEP316 --per_condition_timeout 30`
  - **Constraint:** Verification is external. Claude produces specs/implementation modules only.
- **Phase 2 Stage 3b (block mode + egress allowlist) — VERIFIED on real hardware:**
  - `agent/bpf/probe.c`: two BPF maps (`pg_config`, `egress_allow_ipv4`) + block logic via `bpf_send_signal(9)`.
  - `scripts/pc-smoke-test.sh`: one-command build+run+verify. Run with `sudo bash scripts/pc-smoke-test.sh`.
- **Phase 2 Stage 2 (Z3 proofs):** `tests/proofs/test_z3_properties.py`: P1–P10. `_MAX_OTHER_SCORE` updated 19→24 (Sprint 1).
- **Phase 2 Stage 1 (auto-remediation):** `remediate.py` `WorkflowRemediator` operational.
- **Test suite:** `python -m pytest test_analyzer.py test_consequence_engine.py tests/ -q` → **374 passed, 17 skipped** without Z3/CrossHair; **391 passed** with them installed (`tests/proofs/` 19 tests) (2026-10-26).
- **Open findings:** INC-3 (direct push to main).
- **GitHub App:** App ID 3856270, Installation ID 135500427. Both repos confirmed in scope.
- **Harness CI:** 41 test cases (38 original + RT01/RT02/RT03), regression runner operational with `--mode runtime`.
- **Blockers:** None.

---

## What PayloadGuard Is

A GitHub Action + Python CLI that analyses pull requests for destructive payloads before merge. It does not look for bugs — it looks for PRs that would catastrophically gut the codebase (mass deletions, structural wipeouts, deceptive descriptions). Org: **PayloadGuard-PLG** (formerly DarkVader-PLG, migrated after account suspension).

**Repos:**
- `PayloadGuard-PLG/payload-consequence-analyser` — the analyser (this repo)
- `PayloadGuard-PLG/payloadguard-test-harness` — integration test harness

---

## Architecture

### Nine-Layer Analysis (`analyze.py`)

| Layer | What it does | Key class/function |
|---|---|---|
| L1 Surface | File/line counts, permission changes, symlinks | `PayloadAnalyzer.analyze()` |
| L2 Forensic | Critical path regex matching on deleted files + added file content scan | `CRITICAL_PATH_PATTERNS`, `_scan_added_file_content()` |
| L2b SCA | Manifest diff scanning vs `allowlist.yml` on the target branch (opt-in; keys `python`, `npm`, `go`, `rust`) | `_parse_added_packages()`, `_load_allowlist()` |
| L2c Actions Poisoning | Added/modified workflow files: base64, credential harvest, OIDC elevation, typosquatted consumers | `_scan_github_actions_poisoning()` |
| L2d AI Config Poisoning | Added/modified AI tooling config files: SessionStart hooks, folder-open tasks, lifecycle script hijacks, binding.gyp shell chains, Cursor NL imperatives, hidden Unicode, MCP local server commands | `_scan_ai_tooling_configs()` |
| L3 Consequence | Severity scoring → SAFE/REVIEW/CAUTION/DESTRUCTIVE | `_assess_consequence()` |
| L4 Structural | AST diff — named class/function/constant deletions | `StructuralPayloadAnalyzer` |
| L4b PLI | Semantic consistency — PR description vs diff, commit vs content, old vs new function | NOT ACTIVE — reverted |
| L4b Complexity | McCabe V(G) advisory for newly added Python fns | inside `analyze_structural_drift()` |
| L5a Temporal | Branch age × target velocity drift score | `TemporalDriftAnalyzer` |
| L5b Semantic | PR-MCI three-phase heuristic — deceptive description detection | `SemanticTransparencyAnalyzer` |
| L5c Runtime | eBPF tracepoint agent — execve/connect/ptrace/procmem, audit+block | `agent/`, `_load_runtime_events()` |
| SCG Consequence (`consequence.v1`) | 5-stage symbol matching + D01–D10 differential consequence detectors (`shadow`/`advisory`/`enforce`) | `consequence_engine.py`, `ConsequenceEngine` |

### Key Files

```
analyze.py                  — core analyser, all layers, CLI entry point
structural_parser.py        — AST & Tree-sitter SymbolFact v1 + legacy node extraction (Python/JS/MJS/CJS/TS/TSX/MTS/CTS/Go/Rust/Java)
consequence_engine.py       — Semantic Change Graph (SCG) 5-stage matcher & D01–D10 consequence detectors
post_check_run.py           — posts GitHub Check Run via App JWT (RS256)
remediate.py                — auto-remediation: resolves action tags to SHAs, opens PR
action.yml                  — GitHub Action composite wrapper
agent/                      — eBPF runtime defence agent (Go + cilium/ebpf)
agent/bpf/probe.c           — 4 tracepoint probes + pg_config/egress_allow_ipv4 BPF maps
scripts/pc-smoke-test.sh    — one-command build+verify on real kernel
test_analyzer.py            — legacy, layer, policy, Action and packaging pytest suite (311 tests)
test_consequence_engine.py  — SCG & consequence engine pytest suite (61 tests)
tests/proofs/               — Z3 formal property proofs (P1–P10) + CrossHair pytest wrapper
verification/        — CrossHair verification targets: consequence_pure (C1-C12), temporal_pure (T1-T7), structural_pure (S1-S7), semantic_pure (M1-M9)
allowlist.yml        — SCA package allowlist (user-created, read from the target branch, not in repo by default)
payloadguard.yml     — per-repo threshold and consequence-mode config (user-created, read from the target branch, not in repo by default)
AUDIT_LOG.md         — architectural review findings + incident reports
WHITEPAPER.md        — full technical specification
DEVLOG.md           — chronological session log
```

### Scoring

- Structural CRITICAL: +5
- Security file deleted: +5
- Actions poisoning CRITICAL signal: +5
- AI config poisoning CRITICAL signal: +5
- Unverified dependency (SCA): +3 if any added package is not allowlisted (not per package)
- Actions poisoning HIGH signal: +3
- AI config poisoning HIGH signal: +3
- Critical path deleted: +2
- Added file content flags (CI triggers/shell): +2 per match, capped at +4
- Line/file/ratio flags: up to +4 (capped, correlated dims)
- Branch age: +1/+2/+3
- Thresholds: score >=5 -> DESTRUCTIVE, >=3 -> CAUTION, >=1 -> REVIEW
- MAX_SCORE: 36

### Config (`payloadguard.yml` on the target branch, optional)

```yaml
thresholds:
  branch_age_days: [90, 180, 365]
  files_deleted: [10, 20, 50]
  lines_deleted: [5000, 10000, 50000]
  structural:
    deletion_ratio: 0.20
    min_deleted_nodes: 3
    complexity_threshold: 15
sca:
  fail_on_unknown: true
consequence:
  enabled: true
  mode: shadow          # shadow | advisory | enforce (overridden by --consequence-mode / PAYLOADGUARD_CONSEQUENCE_MODE)
  max_repo_files: 200
```

---

## Current Version

`__version__ = "1.6.0"` (`analyze.py` / `pyproject.toml`). Tags: `v1.5.0` → `93f94f9`; `v1.6.0` → `6c3df91` (published to PyPI 2026-10-26). PyPI had 1.3.0 as its latest release: the v1.4.0 and v1.5.0 tag builds failed (§V3), so 1.6.0 is the first PyPI release since 1.3.0.

### v1.6.0 changes (2026-10-26) — v1.5.0 audit fixes
- §V1 (PR #102): `payloadguard.yml` and `allowlist.yml` are read from the target branch, not the PR merge result (`load_config(repo_path, ref)`, `_load_allowlist(repo_path, ref)`).
- §V2 (PR #103/#104): `action.yml` and the repository workflow scan the PR head commit (`github.event.pull_request.head.sha`) instead of the head branch name.
- §V3 (PR #105): `consequence_engine` listed under `py-modules`; `pip install .` and `python -m build` work again.
- §V4 (PR #106): D01 reports changed source in languages without a structural parser as `UNSUPPORTED_EXTENSION` (WARN).
- §V5/§V6/§V7 (PR #107): action `verdict` output reports REVIEW/CAUTION; `consequence-mode` action input and `--consequence-mode` > `PAYLOADGUARD_CONSEQUENCE_MODE` > `payloadguard.yml` precedence; `.mjs`/`.cjs`/`.mts`/`.cts` parsed with the JS/TS grammars.
- §V10: `TemporalDriftAnalyzer.analyze_drift()` raises `ValueError` for non-finite age or velocity; `temporal_pure.py` precondition `math.isfinite(target_velocity)`.
- §V11: `main()` reconfigures stdout/stderr with `errors="replace"`; a non-UTF-8 stdout (redirected output on Windows) no longer turns the verdict's exit code into 1.
- Packaging: `requires-python = ">=3.11"` (was `>=3.8`; Python 3.8 cannot import `structural_parser.py`, whose module-level `dict[str, str]` annotation is evaluated at import; 3.9 and 3.10 are untested). Classifiers 3.11–3.14.
- Verification: Dafny run #16 (9 verified, 0 errors), CrossHair 36 postconditions with 0 counterexamples, Z3 P1–P10 (P9 vacuous, §V8 open). Docs brought to v1.6.0.
- Tests: 388 passed with Z3/CrossHair installed (311 `test_analyzer.py`, 61 `test_consequence_engine.py`, 16 `tests/proofs/`); 373 passed, 15 skipped without them.

### v1.5.0 changes (2026-10-25, PR #101, tag `v1.5.0`)
- `D08_WORKFLOW_INTEGRITY`: untrusted expression injection in `run:`, `pull_request_target` untrusted checkout, SHA pin downgrade, `continue-on-error`/`write-all` gate weakening, `workflow_run` artifact poisoning, unpinned third-party actions (first-party `actions/*`, `github/*` excluded).
- `D09_TEST_EROSION`: tautological assertion replacement and newly skipped tests.
- `D10_MIGRATION_PERSISTENCE_LOSS`: `TRUNCATE` / `DROP DATABASE|SCHEMA`, multi-line SQL tokenisation, forward-vs-rollback isolation (Alembic, Knex/TypeORM/Sequelize, Rails, Goose/sql-migrate, Django), framework-aware irreversibility.
- `D05` build wrapper tampering (`mvnw`, `gradlew`, `Makefile`, `build.sh`).
- `structural_parser.py`: `_collect_python_const_bools` traverses nested function scopes (no false short-circuit flags for `nonlocal` mutation).
- Tests: 330 passed (284 `test_analyzer.py` + 46 `test_consequence_engine.py`).

### v1.4.0 changes (2026-10-23)
- Feature: SCG Consequence Engine (`consequence.v1`) in the single module `consequence_engine.py` + `SymbolFact` v1 extraction in `structural_parser.py` across Python (`ast`) and JS/TS/Go/Rust/Java (`tree-sitter`).
- Detectors (`D01`–`D06` v2): `D01_PARSER_INCOMPLETE`, `D02_BODY_WEAKENING` / `D02_AMBIGUOUS_REFACTOR` (5-stage rename/move reconciliation with gutting detection), `D03_COMPOUND_LOSS` (resolves `A03` distributed deletion and `A06` compound threshold gaming), `D04_PUBLIC_API_BREAK` v2 (cross-file and aliased caller resolution), `D05_BUILD_DEPENDENCY_DELTA`, and `D06_GUARD_REGRESSION` v2 (guard condition extraction and non-hollow guard removal detection).
- Usability & Reporting: CLI (`print_report`), Markdown (`<details><summary>Evidence & Remediation</summary>`), and SARIF 2.1.0 (`--save-sarif`) output surfaces; `--consequence-mode {shadow,advisory,enforce}`.
- Feature: L2d AI tooling config poisoning detection — `_scan_ai_tooling_configs()` + 8 surface-specific helper functions (`_check_agent_settings_json`, `_check_vscode_tasks`, `_check_cursor_rule`, `_check_package_json_scripts`, `_check_composer_json`, `_check_gemfile`, `_check_binding_gyp`, `_check_mcp_json`).
- Signals: `command_in_session_hook` (CRITICAL), `command_in_folder_open_task` (CRITICAL), `lifecycle_script_hijack` (CRITICAL), `binding_gyp_command_substitution` (CRITICAL), `gemfile_system_call` (CRITICAL), `composer_post_install` (CRITICAL), `cursor_nl_exec_imperative` (HIGH), `hidden_unicode` (HIGH), `mcp_local_server_command` (HIGH).
- `_assess_consequence`: new `ai_config_poisoning_flags` / `ai_config_poisoning_critical` params. Step 9 scoring block mirrors L2c (CRITICAL +5, HIGH +3).
- `_scan_added_file_content`: AI config paths excluded to prevent double-scoring (mirrors L2c exclusion pattern).
- MAX_SCORE: 31 → 36.
- Verification: `consequence_pure.py` `_MAX_SCORE` 31→36, POST-12 contract. `assess_consequence.dfy` `MAX_SCORE` 31→36, POST-12 postcondition. `test_z3_properties.py` `_MAX_OTHER_SCORE` 19→24.
- Tests: 315 passed (`284` in `test_analyzer.py` + `31` in `test_consequence_engine.py`).
- Docs: `README.md`, `CLAUDE.md`, `SYSTEM_BLUEPRINT.md`, `WHITEPAPER.md`, `DEVLOG.md`.

### v1.3.0 changes
- PLI L4b evaluated and reverted. PLI integration (PR #73) was implemented and regression-tested (34 stable cases, 2026-05-29). Result: 2 true positives (A03 adversarial/slow-deletion, A06 adversarial/threshold-gaming — both previously bypassing), 3 false positives (WS07 safe-clean-workflow, RT02 postinstall-curl, RTA03 prt-untrusted-checkout). Root cause: PLI's L2 LLM analysis interprets code diff summaries as blank AI responses, generating critical findings on legitimate safe PRs. Reverted from scoring path. MAX_SCORE reverted 36→31.
- Fix (RTA02): `_scan_github_actions_poisoning()` credential_harvest loop now checks normalized content — multiline curl with continuation lines detected. Expected verdict DESTRUCTIVE confirmed.
- CI: `trigger-regression.yml` changed to manual-only — removed push-to-main auto-trigger that was flooding Claude Code General conversation session with ~200 GitHub events per push.
- Refactor: PLI R&D files deleted from repo root. Stale dev branches cleaned up. analyze.py: unused `import os` removed, dead `hasattr(self.config, 'actions')` guard removed, `_iter_workflow_file_diffs()` helper extracted to deduplicate workflow blob-reading boilerplate.
- Docs: README restructured — formal verification elevated to second section, AI-optimised layout (PR #82, merged `af37447`).

### v1.2.0 changes
- Feature: L2c GitHub Actions poisoning detection — base64 payload, credential harvest, dormant trigger, forged bot author, OIDC elevation (incl. `oidc_elevation_typosquatted` CRITICAL), pull_request_target signals
- Feature: L5b v2 PR-MCI heuristic engine — three-phase (Linguistic Lexer → Diff Profiler → Cross-Correlation), mci_score ∈ [0,1], five signals (V_s/V_o/V_f/V_r/V_e)
- Feature: L5c eBPF runtime defence agent — 4 tracepoints, audit+block mode, egress allowlist, kernel-side `bpf_send_signal(9)`. Verified on WSL2 + GitHub Actions runners.
- Feature: INC-1/INC-4 fix — `_scan_added_file_content()` scans added non-code files for CI triggers and shell execution patterns (+2/match, capped +4)
- Fix: L2 content scanner now excludes `.github/workflows/` files — L2c is the exclusive handler, preventing double-scoring
- Fix: Exit code table corrected — CAUTION exits 0, only DESTRUCTIVE exits 2
- Test suite: 267 pass, 7 skip

### v1.1.0 changes (branch `claude/initial-setup-WO53R`)
- Fix 1.1: Cross-file structural aggregation requires BOTH count AND ratio (was count-only)
- Fix 1.3: YAML parse errors emit WARNING to stderr instead of swallowing silently
- Fix 2.1: JS/TS parser now tracks all `variable_declarator` names (const/let/var, not just arrow fns)
- Fix 3.1: GitHub Check Run summary uses `_safe_truncate()` — cuts at newline, closes open fences
- Fix 3.2: `cryptography` import guard at module load in `post_check_run.py`
- Feature A: SCA dependency scan (L2b) — opt-in via `allowlist.yml`
- Feature B: McCabe complexity advisory for newly added Python functions (no score impact)

---

## Open Findings (from AUDIT_LOG.md)

| ID | Description | Severity | Priority |
|---|---|---|---|
| INC-3 | Direct push to main -> L5b returns UNVERIFIED but raises no flag | MEDIUM | Backlog |
| §2.3 | Single-branch clone / detached HEAD raises BadName exception | MEDIUM | Backlog |
| §H1 | Harness fixture aging: six CAUTION-expected stable cases reach DESTRUCTIVE for branch age alone against a harness `main` commit dated from 2026-11-22 | MEDIUM | Open — decision needed |
| §H2 | RTA01 expects REVIEW from a content-scan signal removed in v1.2.0; REVIEW now comes from branch age only | LOW | Open — decision needed |
| §H3 | Harness `REGRESSION_PAT` returns 401; live regression cannot run | MEDIUM | Open — secret must be replaced |
| WS03 | workflow-security/dormant-trigger: expected DESTRUCTIVE, getting CAUTION (score=3) | MEDIUM | **RESOLVED** — test expectation corrected (see DEVLOG 2026-05-31) |

## Vericoding Plan (from `payloadguard-vericoding-plan.md` on main)

| Phase | Tool | Target | Status |
|---|---|---|---|
| 1 | Z3 SMT | L3 scoring — 10 properties (P1–P10) | Done — `tests/proofs/test_z3_properties.py` |
| 2 | CrossHair | All 4 layers — C1–C12, T1–T7, S1–S7, M1–M9 | Done — `verification/consequence_pure.py`, `temporal_pure.py`, `structural_pure.py`, `semantic_pure.py` |
| 3 | Nagini | `_assess_consequence()` — heap/null safety | **SKIPPED** — pure integer scorer; no heap or concurrency; toolchain cost (Java, Viper JAR, Python ≤3.12) adds no theorem beyond CrossHair |
| 4 | Dafny | L3/L4/L5a reference implementation vs spec | Done — `verification/dafny/assess_consequence.dfy`, `structural_drift.dfy`, `temporal_drift.dfy`; CI: `verify-dafny.yml`; last run #16 (2026-10-26): 9 verified, 0 errors |
| 5 | Publication | `VERIFICATION.md` public summary | Done — three-method summary, Dafny row added |

**Constraint:** Verification is always external. Claude writes specs and implementation modules; external parties run the tools and commit logs.

---

## PC Setup — eBPF Agent (Stage 3b)

When moving to a PC (Ubuntu 22.04/24.04 or WSL2 with kernel ≥5.15):

```bash
# 1. Pull latest
git pull origin main

# 2. One-shot smoke test (builds, runs, fires all 4 event types, checks results)
sudo bash scripts/pc-smoke-test.sh

# 3. Manual run
cd agent
go generate ./...                          # recompile BPF (only needed after probe.c edits)
go build -o ../dist/pg-agent-linux-amd64 .
sudo ../dist/pg-agent-linux-amd64 --mode=audit --dry-run

# 4. Block mode with policy
cat > /tmp/policy.yaml << 'EOF'
egress:
  allow:
    - github.com
    - api.github.com
    - 127.0.0.1
EOF
sudo ../dist/pg-agent-linux-amd64 --mode=block --policy=/tmp/policy.yaml
```

Kernel requirement check: `zcat /proc/config.gz | grep CONFIG_KPROBES` — must be `=y`.
The agent preflight canary will warn and exit 0 gracefully if tracepoints are unavailable.

---

## CI trust boundary

Untrusted GitHub context values must never reach a `run:` body. Actions substitutes `${{ }}` before
bash parses the script, so a branch name or PR title containing shell metacharacters is executed as
code, and quoting the expression does not help. Pass the value through the step's `env:` block and
dereference it as a quoted shell variable:

```yaml
- name: Example
  env:
    PG_HEAD_REF: ${{ github.head_ref }}
  run: some-command "$PG_HEAD_REF"
```

This applies to `github.head_ref`, `github.base_ref`, `github.ref`, `github.actor` and any
`github.event.*` field, in `action.yml` and in every workflow. `$GITHUB_ACTION_PATH` and
`$GITHUB_WORKSPACE` are available as environment variables and are preferred over interpolating
their expression equivalents.

`TestOwnWorkflowsNotInjectable` parses this repository's own action and workflow files and fails on
reintroduction. It is a project invariant, not a general proof: `actionlint` and `zizmor` are the
broad checks and belong in CI.

## Development Rules

- **Assumption is the mother of all fuck ups. Don't guess, verify or ask. Don't make decisions that require user input. If you hit a 404 when pushing, stop — it is likely PayloadGuard.org blocking the push. Verification of code quality, determinism, and honest capability is everything; otherwise the work means nothing.**
- **Push:** `git push -u origin <branch>` — MCP push works now but PC push is equally fine
- **CLAUDE.md is updated on every change, no exceptions.** Every code change, fix, finding, doc update, or architectural decision goes into the Handover block before the session ends. Stale handovers cause real work loss. This includes architecture table, key files, scoring, open findings, and version changelog — not just the Handover block.
- **Read CLAUDE.md at session start and verify every section is current before touching code.**
- **Tests:** Run `python -m pytest test_analyzer.py -v` before every commit -- must stay green
- **Commit style:** Imperative, specific, with test count in body. See git log for examples.
- **Documentation style:** Professional and concise throughout. No informal, casual, or whimsical language in any documentation, commit messages, comments, or README content. State facts directly. Every sentence must earn its place.

---

## Environment

- Python 3.11+ (`requires-python >=3.11`; 3.11 in CI and the Action, 3.14 verified locally)
- Dependencies: `pip install -r requirements.txt` — GitPython, PyYAML, PyJWT, requests, tree-sitter + 6 grammar packages; z3-solver and crosshair-tool for the proof tests
- Test: `python -m pytest test_analyzer.py test_consequence_engine.py tests/ -q` (391 passed with the proof tools; 374 passed, 17 skipped without)
- CI: GitHub Actions via `action.yml` -- runs on every PR in consumer repos

---

## How to Start a New Session

1. Read this file (`CLAUDE.md`) -- you now have full context
2. Check the **Handover** block at the top for what's in flight
3. Run `git log --oneline -5` to confirm branch state
4. Run `python -m pytest test_analyzer.py -v` to confirm green baseline
5. Begin work

**Update the Handover block before ending every session.**

---

## Architecture & Blueprints

### Rules for Tracking the Analysis Pipeline

The 9-layer pipeline and its formal verification harness must remain consistent across `analyze.py`, `SYSTEM_BLUEPRINT.md`, `VERIFICATION.md`, `VERIFICATION_SPEC.md`, and `WHITEPAPER.md`. When any of the following change, update **all affected documents in the same commit** — partial updates cause audit drift.

#### 1. Layer definitions

The canonical layer table lives in the Architecture section of this file (see above). Any new signal, renamed layer, or scoring change requires:
- Update the layer table here
- Update the Scoring section here
- Update `README.md` (Layer reference table)
- Update `WHITEPAPER.md` (the affected section)
- Update `SYSTEM_BLUEPRINT.md` (Pipeline Flow section)
- Update the relevant verification module in `verification/` if the changed layer is formally verified

#### 2. Scoring changes

Scoring is triple-verified (CrossHair, Z3, Dafny). Any change to thresholds, signal weights, or the deletion-dimension cap must be propagated to:
- `analyze.py` `_assess_consequence()` and `DEFAULT_CONFIG`
- `verification/consequence_pure.py` (CrossHair) — constants `_MAX_SCORE`, thresholds, and all `post:` contracts
- `verification/dafny/assess_consequence.dfy` — `MAX_SCORE`, helper functions, and `AssessConsequence` postconditions
- `tests/proofs/test_z3_properties.py` — Z3 property bounds
- `README.md` and `WHITEPAPER.md` scoring reference tables

Do not change scoring constants in one place and leave others stale. CrossHair and Dafny will catch mismatches on next verification run, but CI does not run them on every push — a stale spec is a silent lie.

#### 3. Formal verification status

Tracking table: every verified layer must have an entry in `VERIFICATION.md` and `VERIFICATION_SPEC.md`. Current status:

| Layer | CrossHair | Z3 | Dafny |
|---|---|---|---|
| L3 Consequence | C1–C12 + POST-12 (`consequence_pure.py`) | P1–P10 (`test_z3_properties.py`) | POST-1–12 (`assess_consequence.dfy`) |
| L4 Structural | S1–S7 (`structural_pure.py`) | — | S1–S7 (`structural_drift.dfy`) |
| L5a Temporal | T1–T7 (`temporal_pure.py`) | — | T1–T8 (`temporal_drift.dfy`) |
| L5b Semantic | M1–M9 (`semantic_pure.py`) | — | — |

When adding a new verified contract:
1. Add the contract to the relevant `verification/*_pure.py` file
2. Add a corresponding test in `tests/proofs/test_crosshair_contracts.py` (CrossHair) or `test_z3_properties.py` (Z3)
3. Update `VERIFICATION.md` and `VERIFICATION_SPEC.md`
4. Update this table

#### 4. Forensic logic invariants

The following invariants are machine-verified and must not be violated by any code change:

- **Score non-negativity:** `severity_score >= 0` at all times (POST-2 / C: severity_score >= 0)
- **Score upper bound:** `severity_score <= 36` (MAX_SCORE = 36; POST-3)
- **Verdict bijection:** Every score maps to exactly one verdict; every verdict maps to exactly one score range (POST-4–7)
- **Safety-critical floor:** `security_file_deletions > 0` → DESTRUCTIVE; `structural_severity == CRITICAL` → DESTRUCTIVE; `actions_poisoning_critical` → DESTRUCTIVE; `ai_config_poisoning_critical` → DESTRUCTIVE (POST-8/9/10/12)
- **Empty-input guarantee:** All-zero inputs → SAFE; no false positives on empty diffs (POST-11a)
- **Deletion dimension cap:** Three correlated deletion sub-scores (files/ratio/lines) are collapsed to `min(4, max + 1 if ≥2 active)` — prevents triple-counting

These invariants hold over the entire input domain by construction. If a code change requires relaxing one, the verification proofs must be updated before merging.

#### 5. Branch analysis tracking

When investigating a specific test branch (harness fixture or real PR), record findings in `AUDIT_LOG.md` with:
- Branch name and test case ID
- Expected verdict and actual verdict
- Score breakdown: which signals fired, which did not, and why
- Root cause if verdict is wrong
- Fix or deferral decision

Do not leave open verdict mismatches undocumented. If a case is deferred, add it to the Open Findings table in this file.

#### 6. SYSTEM_BLUEPRINT.md sync

`SYSTEM_BLUEPRINT.md` is the single authoritative reference for the repository structure and pipeline flow. It must be updated whenever:
- A new module is added or removed from the production path
- A new layer or sub-layer is added
- The AUDIT_LOG.md generation path changes
- Production dependencies change (requirements.txt or agent/go.mod)

`SYSTEM_BLUEPRINT.md` is a generated document — treat it as derived from the codebase, not as a source of truth. When in doubt, the code wins.
