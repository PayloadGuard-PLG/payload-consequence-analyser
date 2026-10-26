# PayloadGuard

**Version:** 1.6.0 &nbsp;|&nbsp; **Status:** Production &nbsp;|&nbsp; **Updated:** October 2026

[![Dafny Verification](https://github.com/PayloadGuard-PLG/payload-consequence-analyser/actions/workflows/verify-dafny.yml/badge.svg)](https://github.com/PayloadGuard-PLG/payload-consequence-analyser/actions/workflows/verify-dafny.yml)
[![Pytest Suite](https://img.shields.io/badge/pytest-391%20passed-brightgreen.svg)](#test-suite--formal-verification)
[![Formal Proofs](https://img.shields.io/badge/formal%20proofs-36%20contracts%20%7C%2010%20Z3%20%7C%2012%20Dafny-blue.svg)](PROOFS.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Formally verified** — 36 CrossHair contracts • 10 Z3 SMT proofs • 12 Dafny postconditions • **391 tests pass (100%)** • 3 independent proof methods. → [`PROOFS.md`](PROOFS.md)

PayloadGuard is a GitHub Action and pre-merge consequence analysis engine that forensically scans pull requests for destructive, deceptive, or supply-chain payloads before they reach your default branch.

It was engineered for the class of attacks and human errors that slip past standard linters, test runners, and merge queues: branches held open for months that land as a *"minor fix"* and wipe the codebase in a single merge, tests that pass only because assertions were silently replaced with tautologies (`assert True`), database migrations that permanently wipe production data without rollback procedures, CI workflows modified to execute untrusted PR expressions, and security guards neutralized with boolean short-circuits (`if not verify() and False:`). 

Wire PayloadGuard to your branch protection rules, and catastrophic pull requests are blocked automatically.

---

## Key Benefits

- **Deterministic & Instant CI Integration:** Runs in seconds directly inside GitHub Actions with **zero LLM dependency**, **zero external API latency**, and **zero non-determinism**.
- **Semantic Change Graph (SCG) Consequence Engine (`consequence.v1`):** Understands high-level program structure across Python, JavaScript (`.js`, `.jsx`, `.mjs`, `.cjs`), TypeScript (`.ts`, `.tsx`, `.mts`, `.cts`), Go, Rust, and Java. Changes to source code in other languages are reported as incomplete coverage (`D01`). Distinguishes benign symbol renames and cross-file moves from hollow stubs, broken callers, and deleted capabilities.
- **Catches What Test Suites and Linters Miss:**
  - **Test Erosion (`D09`):** Flags tests gutted into tautologies (`assert True`, `expect(true).toBe(true)`) or newly skipped (`@pytest.mark.skip`, `t.Skip()`).
  - **CI Workflow Integrity (`D08`):** Blocks untrusted expression injection in `run:` shell blocks, `pull_request_target` untrusted checkout ("Pwn Request"), action SHA pin downgrades, and `continue-on-error: true` gate weakening.
  - **Migration & Persistence Protection (`D10`):** Blocks `TRUNCATE` and `DROP DATABASE/SCHEMA` in automated migrations; isolates forward migration drops from rollback procedures across Alembic, Knex, Rails, Goose, and Django.
  - **Security Guard Regressions (`D06`):** Detects removed auth decorators, dropped transaction rollbacks, inverted guard polarities, and `and False` / `|| true` short-circuits.
  - **Build Wrapper Tampering (`D05`):** Detects unauthorized remote downloads or reverse shells (`curl | sh`) inside `mvnw`, `gradlew`, `Makefile`, and `build.sh`.
- **Formally Verified Decision Engine:** Scoring thresholds, severity floors, and verdict bijections are mathematically proven across CrossHair symbolic execution, Z3 SMT theorem proving, and Dafny machine-checked proofs.
- **Actionable Remediation Guidance:** Every finding includes exact line numbers, source snippets, affected symbols, and precise remediation advice formatted in interactive, collapsible GitHub markdown comments and SARIF 2.1.0 output.

---

## What PayloadGuard Detects

| Threat Category | Detector / Layer | Real-World Attack / Error Scenario | Default Policy |
|---|---|---|---|
| **Mass Deletion Disguised as Refactor** | `L1`, `L2`, `L4` | 312-day-old branch submitted as *"minor syntax fix"*, deleting 60 files and 11,967 lines | `BLOCK` |
| **Structural Gutting & Stub Replacement** | `D02_BODY_WEAKENING` | Security or authentication methods renamed and gutted into `pass`, `...`, or `return None` stubs | `BLOCK` |
| **Distributed Loss & Threshold Gaming** | `D03_COMPOUND_LOSS` | Removing 1 security function per file across 5 files (`A03`) or padding deleted methods with trivial getters (`A06`) | `BLOCK` |
| **Broken Cross-File Callers & API Breaks** | `D04_PUBLIC_API_BREAK` | Deleting exported functions or tightening required parameters while surviving callers (including aliased imports) still invoke the old contract | `BLOCK` |
| **Build Wrapper Script Tampering** | `D05_BUILD_DEPENDENCY_DELTA` | Remote script execution or reverse shell (`curl \| sh`) injected into `mvnw`, `gradlew`, `Makefile`, or `build.sh` | `BLOCK` |
| **Manifest Dependency Drift** | `D05_BUILD_DEPENDENCY_DELTA` | Dependency added to `package.json` or `pyproject.toml` without accompanying lockfile update | `REVIEW` |
| **Security Guard & Rollback Regression** | `D06_GUARD_REGRESSION` | Removing `@require_auth`, dropping `self._rollback()`, inverting guard polarity (`if not verify()` → `if verify()`), or inserting `and False` short-circuits | `BLOCK` |
| **Untrusted CI Expression Injection** | `D08_WORKFLOW_INTEGRITY` | Interpolating untrusted context (`${{ github.event.pull_request.title }}`) directly inside `run:` shell blocks (W02 / CWE-78) | `BLOCK` |
| **Pwn Request Checkout** | `D08_WORKFLOW_INTEGRITY` | Combining privileged `pull_request_target` trigger with checkout of untrusted pull request head ref (W01) | `BLOCK` |
| **Action SHA Pin Downgrade** | `D08_WORKFLOW_INTEGRITY` | Action downgraded from an immutable 40-character commit SHA to a mutable tag or branch (`@v4`, `@main`) | `REVIEW` |
| **CI Gate Weakening** | `D08_WORKFLOW_INTEGRITY` | Adding `continue-on-error: true` to required test/lint steps or adding broad `permissions: write-all` | `REVIEW` |
| **Privileged Artifact Poisoning** | `D08_WORKFLOW_INTEGRITY` | Privileged `workflow_run` trigger downloading and unpacking untrusted artifacts without sandboxing | `REVIEW` |
| **Test Assertion Erosion** | `D09_TEST_EROSION` | Substantive test assertions replaced with tautologies (`assert True`, `expect(true).toBe(true)`), keeping CI green while gutting coverage | `BLOCK` |
| **Newly Skipped Tests** | `D09_TEST_EROSION` | Adding test-skip decorators (`@pytest.mark.skip`, `@pytest.mark.xfail`, `it.skip`) or runtime skip calls (`pytest.skip()`, `t.Skip()`) | `REVIEW` |
| **Catastrophic Persistence Wipe-Out** | `D10_MIGRATION_PERSISTENCE_LOSS` | Migration executing `TRUNCATE TABLE` or `DROP DATABASE` / `DROP SCHEMA` on persistent data | `BLOCK` |
| **Irreversible Schema Drop** | `D10_MIGRATION_PERSISTENCE_LOSS` | Dropping tables or columns with empty/missing `downgrade()`, Rails `change` without block, or Django `RunSQL` without `reverse_sql` | `BLOCK` |
| **Destructive Migration Drop** | `D10_MIGRATION_PERSISTENCE_LOSS` | Dropping persistent table or column in forward migration (with working rollback procedure) | `REVIEW` |
| **Workflow Actions Poisoning & OIDC** | `L2c` | Workflow files modified to exfiltrate secrets, steal OIDC tokens, or forge CI identities | `BLOCK` |
| **AI Tooling Config Poisoning** | `L2d` | Malicious `.claude/settings.json`, `.cursor/rules/*.mdc`, `.vscode/tasks.json`, or lifecycle scripts executing on folder open | `BLOCK` |
| **Deceptive PR Descriptions** | `L5b` | PR description says *"minor copy fix"* while the diff alters authentication or drops database tables | Escalates the verdict one level (SAFE/REVIEW → CAUTION, CAUTION → DESTRUCTIVE) |

The policy column is each finding's recommendation. Consequence-detector (`Dxx`) findings change the verdict and exit code only in `advisory` or `enforce` mode; the default mode is `shadow` (see [Consequence Modes](#3-consequence-modes)).

---

## Analysis Tiers

PayloadGuard operates across three analysis tiers. Each tier builds on the one before it:

```
┌─────────────────────────────────────────────────────────────┐
│  CORE  (L1 • L2 • L2b • L3)                                 │
│  Surface scan → Forensic file analysis → Weighted scoring   │
│  Zero external dependencies (GitPython, PyYAML, PyJWT)      │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│  STANDARD  (adds L2c • L2d • L4 • L5a • L5b • consequence.v1│
│  + CI workflow integrity (D08) & Actions poisoning (L2c)    │
│  + AI tooling configuration poisoning (L2d)                 │
│  + Semantic Change Graph Consequence Engine (D01–D10)       │
│  + Test erosion (D09) & Migration persistence loss (D10)    │
│  + Temporal drift (L5a) & Semantic transparency (L5b)       │
│  Dependencies: Tree-sitter multi-language grammars          │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│  FULL  (adds L5c)                                           │
│  + eBPF runner runtime agent (execve, egress, ptrace)       │
│  Dependencies: Linux runner with kernel BPF support         │
└─────────────────────────────────────────────────────────────┘
```

---

## SCG Consequence Engine (`consequence.v1`)

The Consequence Engine (`consequence_engine.py`) matches `base` and `head` symbols through a 5-stage Semantic Change Graph (SCG) pipeline:
1. **Exact match:** same file, qualified name and kind.
2. **Renamed-file match:** same qualified name and kind in a file git reports as renamed.
3. **Cross-file move:** same qualified name (or same name with matching signature or body hash) in another changed file.
4. **Container and body-hash rename:** renamed classes/structs matched by member overlap, functions renamed with an identical body hash and signature, and same-scope replacements by a no-op stub.
5. **Residual classification:** anything unmatched is `REMOVED` or `ADDED`.

Transitions: `UNCHANGED`, `MODIFIED`, `GUTTED`, `MOVED`, `MOVED_AND_GUTTED`, `RENAMED`, `RENAMED_AND_GUTTED`, `AMBIGUOUS`, `REMOVED`, `ADDED`. A body counts as gutted when a non-stub symbol becomes a no-op stub, or when three or more statements with calls collapse to at most one statement without calls.

### Consequence Detectors Reference

| Detector ID | Consequence Classes | Epistemic Tier | Default Policy | Description |
|---|---|---|---|---|
| `D01_PARSER_INCOMPLETE` | `ANALYSIS_INCOMPLETE` | `ANALYSIS_INCOMPLETE` | `WARN` / `REVIEW` | File syntax errors, missing grammar packages, or unsupported extensions. |
| `D02_BODY_WEAKENING` | `BODY_GUTTED`, `RENAME_WITH_BODY_WEAKENING`, `AMBIGUOUS_REFACTOR` | `VERIFIED_CONSEQUENCE` | `BLOCK` / `WARN` | Surviving or renamed symbols gutted to no-op stubs (`pass`, `...`, `return None`, empty `{}`). |
| `D03_COMPOUND_LOSS` | `DISTRIBUTED_SYMBOL_LOSS`, `THRESHOLD_GAMING_DELETION` | `VERIFIED_CONSEQUENCE` | `BLOCK` / `REVIEW` | Cross-file sub-threshold deletion (`A03`) and deletion-ratio dilution via trivial getters (`A06`). |
| `D04_PUBLIC_API_BREAK` | `UNRESOLVED_CALLER`, `PUBLIC_API_REMOVAL`, `PUBLIC_API_SIGNATURE_BREAK` | `VERIFIED_CONSEQUENCE` | `BLOCK` / `REVIEW` | Deleted symbols with surviving callers (including aliased imports) or broken signatures. |
| `D05_BUILD_DEPENDENCY_DELTA` | `BUILD_WRAPPER_TAMPERING`, `BUILD_SCRIPT_MODIFICATION`, `DEPENDENCY_LOCKFILE_MISMATCH` | `VERIFIED_CONSEQUENCE` | `BLOCK` / `REVIEW` | Remote script execution in build wrappers (`mvnw`, `gradlew`), lifecycle scripts, or unpinned dependencies. |
| `D06_GUARD_REGRESSION` | `SECURITY_GUARD_REMOVED`, `SECURITY_GUARD_WEAKENED` | `VERIFIED_CONSEQUENCE` | `BLOCK` | Removed auth decorators, dropped transaction rollbacks, inverted polarities, or `and False` short-circuits. |
| `D08_WORKFLOW_INTEGRITY` | `UNTRUSTED_WORKFLOW_EXPRESSION_INJECTION`, `PULL_REQUEST_TARGET_UNTRUSTED_CHECKOUT`, `ACTION_PIN_DOWNGRADE`, `CI_GATE_WEAKENED`, `WORKFLOW_RUN_UNTRUSTED_ARTIFACT`, `ACTION_PIN_UNPINNED` | `VERIFIED_CONSEQUENCE` | `BLOCK` / `REVIEW` / `WARN` | Untrusted expression injection, Pwn Request checkout, SHA pin downgrade, gate weakening, and unpinned 3rd-party actions. |
| `D09_TEST_EROSION` | `TEST_ASSERTION_EROSION`, `TEST_SKIPPED_NEWLY` | `VERIFIED_CONSEQUENCE` | `BLOCK` / `REVIEW` | Test assertions replaced with tautologies (`assert True`) or newly skipped test decorators/calls. |
| `D10_MIGRATION_PERSISTENCE_LOSS` | `CATASTROPHIC_DATA_WIPEOUT`, `IRREVERSIBLE_PERSISTENCE_DROP`, `DESTRUCTIVE_PERSISTENCE_MIGRATION` | `VERIFIED_CONSEQUENCE` | `BLOCK` / `REVIEW` | Automated `TRUNCATE`, `DROP DATABASE`, irreversible table/column drops, or forward schema removals. |

---

## GitHub Action Installation & Setup

### 1. Add Workflow to Your Repository

Create `.github/workflows/payloadguard.yml` in your default branch:

```yaml
name: PayloadGuard Analysis

on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  scan:
    name: PayloadGuard Pre-Merge Consequence Analysis
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write       # Required to post interactive review comments
      security-events: write     # Required if saving SARIF to GitHub Code Scanning

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 0         # Required: full git history needed for merge-base analysis

      - name: Run PayloadGuard Scan
        id: payloadguard
        uses: PayloadGuard-PLG/payload-consequence-analyser@main
        with:
          repo-token: ${{ secrets.GITHUB_TOKEN }}
          pr-description: ${{ github.event.pull_request.body }}
          save-markdown: payloadguard-report.md

      - name: Enforce Merge Policy
        if: always()
        env:
          EXIT_CODE: ${{ steps.payloadguard.outputs.exit-code }}
        run: |
          echo "PayloadGuard scan exited with code: $EXIT_CODE"
          if [ "$EXIT_CODE" = "2" ]; then
            echo "::error::PayloadGuard detected verified DESTRUCTIVE code consequences. Merge is blocked."
            exit 2
          fi
          if [ "$EXIT_CODE" = "1" ]; then
            echo "::error::PayloadGuard encountered an analysis error."
            exit 1
          fi
          echo "PayloadGuard verdict is SAFE, REVIEW or CAUTION. Proceed with review."
```

### 2. Configure Branch Protection (Enforce Blocking)

To prevent pull requests with destructive payloads from merging:
1. In your GitHub repository, navigate to **Settings** → **Branches** → **Branch protection rules**.
2. Select your default branch (e.g., `main`).
3. Check **Require status checks to pass before merging**.
4. Search for and select the `scan` (or `PayloadGuard Pre-Merge Consequence Analysis`) check.
5. Save changes. Any PR with verified destructive consequences (`exit code 2`) will now fail the check and block the merge button.

### 3. Consequence Modes

PayloadGuard supports three policy enforcement modes. The mode is taken from the action's `consequence-mode` input (the CLI's `--consequence-mode`), then the `PAYLOADGUARD_CONSEQUENCE_MODE` environment variable, then `payloadguard.yml`:

| Mode | Behavior | Use Case |
|---|---|---|
| `shadow` *(default)* | Runs all consequence detectors, logs findings in JSON, PR comments, and SARIF, but does not escalate the exit code to `2`. | Initial trial / baseline observation in existing repositories. |
| `advisory` | `BLOCK` and `REVIEW` findings are added to the verdict flags and raise a `SAFE` verdict to `REVIEW`; the exit code is never escalated to `2`. `WARN` findings are reported only. | Team transition / soft enforcement. |
| `enforce` | Any `BLOCK` finding sets the verdict to `DESTRUCTIVE` (exit code `2`); `REVIEW` findings raise a `SAFE` verdict to `REVIEW`. | Production repositories requiring strict pre-merge safety guarantees. |

To enforce blocking mode via your workflow:
```yaml
      - name: Run PayloadGuard Scan (Enforce)
        uses: PayloadGuard-PLG/payload-consequence-analyser@main
        with:
          repo-token: ${{ secrets.GITHUB_TOKEN }}
          pr-description: ${{ github.event.pull_request.body }}
          consequence-mode: enforce
```
Or place a `payloadguard.yml` in your repository root:
```yaml
consequence:
  mode: enforce
```
`payloadguard.yml` is read from the target branch, so a pull request cannot change it for its own scan. The `consequence-mode` input is only as trusted as the workflow file; on `pull_request` events that file comes from the pull request, so protect it with required workflows or CODEOWNERS.

The action's `verdict` output is `SAFE`, `REVIEW`, `CAUTION` or `DESTRUCTIVE`, or `ERROR` when the analysis failed (including an invalid `consequence-mode`, which exits `1`).

---

## Local CLI Usage

You can run PayloadGuard locally or in custom CI pipelines without GitHub Actions:

### Installation via pip

```bash
pip install payloadguard-plg     # Python 3.11+
```

This installs the `payloadguard` command (equivalent to `python analyze.py`).

### From Source

```bash
git clone https://github.com/PayloadGuard-PLG/payload-consequence-analyser.git
cd payload-consequence-analyser
pip install -r requirements.txt
```

### Running Scans

```bash
# Basic scan of a feature branch against main
python analyze.py . feature/my-branch main

# Scan with PR description for Semantic Transparency analysis (Layer 5b)
python analyze.py . feature/my-branch main   --pr-description "Add user profile endpoint and migrate session table"

# Run in strict consequence enforcement mode
python analyze.py . feature/my-branch main --consequence-mode enforce

# Generate JSON, GitHub Markdown, and SARIF 2.1.0 reports
python analyze.py . feature/my-branch main   --save-json reports/scan.json   --save-markdown reports/scan.md   --save-sarif reports/scan.sarif
```

### Exit Codes

| Exit Code | Meaning | Action in CI |
|---|---|---|
| `0` | `SAFE`, `REVIEW`, or `CAUTION` | Proceed with standard peer review |
| `1` | `ANALYSIS_ERROR` | Infrastructure or git execution error |
| `2` | `DESTRUCTIVE` | **Merge blocked** — verified destructive consequence detected |

---

## Configuration (`payloadguard.yml`)

Place `payloadguard.yml` in your repository root to customize rules and thresholds. All fields are optional.

`payloadguard.yml` and `allowlist.yml` are read from the target branch (for example `main`), not from the branch being scanned. A pull request cannot change the policy its own scan runs under; edits to either file take effect once merged.

```yaml
# Consequence Engine Configuration
consequence:
  mode: enforce                       # shadow | advisory | enforce
  max_repo_files: 500                 # max head files indexed for cross-file caller verification

# Structural & Deletion Thresholds
thresholds:
  branch_age_days: [90, 180, 365]     # days → +1/+2/+3 score
  files_deleted:   [10, 20, 50]       # files → +1/+2/+3 score
  lines_deleted:   [5000, 10000, 50000]
  temporal:
    stale:     250                    # drift_score threshold (STALE)
    dangerous: 1000                   # drift_score threshold (DANGEROUS)
  structural:
    deletion_ratio:    0.20           # 20% of symbols deleted → CRITICAL
    min_deleted_nodes: 3

# Software Composition Analysis (SCA)
sca:
  fail_on_unknown: true               # Unverified package in manifest → +3 score

# GitHub Actions Security
actions:
  enabled: true
  critical_signal_score: 5
  high_signal_score: 3
  trusted_oidc_consumers:
    - my-org/custom-deploy-action

# Semantic Transparency Analysis
semantic:
  micro_scope_churn_limit: 50
  insertion_ratio_fix_threshold: 0.9
```

### Approved Dependencies Allowlist (`allowlist.yml`)

Software composition analysis (L2b) runs only when `allowlist.yml` exists in the repository root on the target branch. Packages added in `requirements*.txt`, `pyproject.toml`, `package.json`, `go.mod` and `Cargo.toml` are checked against the list for their ecosystem; with `sca.fail_on_unknown: true` (the default) any unlisted package adds +3 to the score.

```yaml
python:          # requirements*.txt, pyproject.toml
  - requests
  - pydantic
npm:             # package.json
  - express
go:              # go.mod
  - github.com/spf13/cobra
rust:            # Cargo.toml
  - serde
```

---

## Test Suite & Formal Verification

PayloadGuard's consequence and scoring logic is mathematically proven to eliminate non-deterministic scoring errors. A flaw would have to produce an identical error across three independent mathematical frameworks simultaneously:

| Method | Specification & Tool | What is Proven |
|---|---|---|
| **SMT Prover** | **Z3** | Typosquat floor and severity ordering for Actions signals, score monotonicity, SAFE ↔ score below the review threshold, the score upper bound derived from the per-signal model, and the empty-input guarantee (P1–P10). |
| **Symbolic Execution** | **CrossHair** | Postcondition contracts across consequence scoring, structural drift, temporal drift, and semantic transparency (C1–C12, S1–S7, T1–T7, M1–M9). |
| **Machine-Checked Proofs** | **Dafny** | Full input domain coverage and 12 machine-checked postconditions verified with zero verification errors (POST-1–12). |

### Test Metrics

```bash
# Run the complete suite, including the proof tests (needs z3-solver and crosshair-tool from requirements.txt)
python -m pytest test_analyzer.py test_consequence_engine.py tests/ -q
# 391 passed
```

- **Test suite:** **391 passed, 0 failed** (`test_analyzer.py` 311, `test_consequence_engine.py` 61, `tests/proofs/` 19). Without Z3 and CrossHair installed: 374 passed, 17 skipped.
- **Mutation Suite:** **16 / 16 passed** with **0 False Positives and 0 False Negatives** ([`run_mutation_suite.py`](https://github.com/PayloadGuard-PLG/payloadguard-test-harness/blob/main/tools/run_mutation_suite.py)).
- **Harness Manifest Oracle:** **41 / 41 passed** across schema validations and Consequence Engine v1 assertions ([`validate_manifest.py`](https://github.com/PayloadGuard-PLG/payloadguard-test-harness/blob/main/tools/validate_manifest.py)).

Detailed specifications and mathematical proofs are documented in [`VERIFICATION.md`](VERIFICATION.md) and [`PROOFS.md`](PROOFS.md).

---

## What's New in v1.6.0

PayloadGuard **v1.6.0** fixes the defects found in an audit of v1.5.0 (`AUDIT_LOG.md` §V1–§V10) and is the first release published to PyPI since 1.3.0:

1. **Policy cannot be changed by the pull request it judges:** `payloadguard.yml` and `allowlist.yml` are read from the target branch, not the scanned branch.
2. **Fork pull requests are scanned correctly:** the Action scans the pull request head commit instead of resolving the head branch name, which failed for fork branches or matched the base repository's same-named branch.
3. **`consequence-mode` Action input:** `shadow` | `advisory` | `enforce`; the `verdict` output now reports `REVIEW` and `CAUTION`.
4. **Coverage reporting:** changed source in languages without a structural parser is reported by `D01` as incomplete coverage; `.mjs`, `.cjs`, `.mts` and `.cts` are parsed with the JavaScript/TypeScript grammars.
5. **Packaging:** the distribution builds again (`consequence_engine` is shipped); `requires-python` is now `>=3.11`.
6. **Temporal drift:** non-finite branch age or target velocity raises `ValueError` instead of producing a NaN score classified `CURRENT`.
7. **CLI exit codes on Windows:** a console that cannot encode the report's symbols (redirected output on Windows) no longer turns the verdict into exit code 1.
8. **Verification:** Dafny, CrossHair and Z3 re-run against the current specifications; results in [`PROOFS.md`](PROOFS.md).

## What's New in v1.5.0

PayloadGuard **v1.5.0** introduces major enhancements across CI/CD pipeline integrity, test suite preservation, database persistence security, and AST parsing robustness:

1. **`D08_WORKFLOW_INTEGRITY`:**
   - Detects untrusted expression injection in `run:` shell blocks (`${{ github.event.pull_request.title }}`).
   - Blocks `pull_request_target` workflows checking out untrusted PR head code ("Pwn Request").
   - Flags immutable 40-character commit SHA pin downgrades to mutable refs.
   - Detects CI gate weakening via added `continue-on-error: true` flags or broad `permissions: write-all`.
   - Flags privileged `workflow_run` triggers downloading untrusted PR artifacts without sandboxing.
   - Flags newly introduced unpinned third-party actions while excluding official `actions/*` and `github/*` namespaces.
2. **`D09_TEST_EROSION`:**
   - Detects test assertions gutted into tautologies (`assert True`, `expect(true).toBe(true)`), preventing silent test coverage destruction.
   - Detects newly introduced test-skip decorators (`@pytest.mark.skip`, `@pytest.mark.xfail`) and runtime skip calls (`pytest.skip()`, `t.Skip()`).
3. **`D10_MIGRATION_PERSISTENCE_LOSS`:**
   - Blocks catastrophic `TRUNCATE TABLE` and `DROP DATABASE` / `DROP SCHEMA` statements in automated migrations.
   - Tokenizer-based multi-line SQL statement parsing handling inline comments (`/* ... */`, `--`), whitespace, and quoted identifiers (`ALTER TABLE ... DROP COLUMN`).
   - Forward-vs-rollback boundary isolation across Alembic, Knex/TypeORM/Sequelize, Rails ActiveRecord, Goose/sql-migrate, and Django. Drops inside rollback functions emit zero false positives.
   - Framework-aware irreversibility analysis flagging Rails `change` drops without blocks and Django `RunSQL` without `reverse_sql` as `BLOCK`.
4. **`D05` Build Wrapper Tampering:**
   - Detects remote script execution and reverse shell patterns (`curl | sh`, `wget | bash`) inside build wrappers (`mvnw`, `gradlew`, `Makefile`, `build.sh`).
5. **Parser Scope Hardening:**
   - Fixed `_collect_python_const_bools` in `structural_parser.py` to traverse nested function scopes, correctly identifying variables mutated via `nonlocal` or nested assignment and eliminating false-positive short-circuit flags on inner helper functions.

---

## Contributing & Development

```bash
# Clone the repository
git clone https://github.com/PayloadGuard-PLG/payload-consequence-analyser.git
cd payload-consequence-analyser

# Install development dependencies
pip install -r requirements.txt

# Run the full test suite, including the proof tests
python -m pytest test_analyzer.py test_consequence_engine.py tests/ -q
```

All new detectors require corresponding test cases in [`test_consequence_engine.py`](test_consequence_engine.py). Open findings and vulnerability disclosures are tracked in [`AUDIT_LOG.md`](AUDIT_LOG.md).

---

*PayloadGuard is engineered and maintained by [PayloadGuard-PLG](https://github.com/PayloadGuard-PLG).*
