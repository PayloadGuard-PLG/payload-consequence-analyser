# PayloadGuard

[![PyPI](https://img.shields.io/pypi/v/payloadguard-plg.svg)](https://pypi.org/project/payloadguard-plg/)
[![Dafny Verification](https://github.com/PayloadGuard-PLG/payload-consequence-analyser/actions/workflows/verify-dafny.yml/badge.svg)](https://github.com/PayloadGuard-PLG/payload-consequence-analyser/actions/workflows/verify-dafny.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

PayloadGuard analyses a pull request before it merges and reports whether the change would destroy, disable or hide something important. It runs as a GitHub Action or from the command line, compares the branch with its target using git alone, and returns one of four verdicts (`SAFE`, `REVIEW`, `CAUTION`, `DESTRUCTIVE`) with an exit code that a branch protection rule can enforce.

It targets changes that pass ordinary review and CI:

- a long-lived branch merged as a "minor fix" that deletes most of the code base;
- tests whose assertions were replaced by tautologies, or that were silently skipped;
- migrations that drop data with no working rollback;
- workflows that run untrusted pull request input, or that exfiltrate secrets;
- security guards disabled with `and False`, removed decorators or inverted conditions;
- AI tooling configuration that executes commands when a folder is opened;
- a PR description that contradicts what the diff does.

The analysis is deterministic and local. It calls no LLM and no third-party service, and repository source does not leave the runner.

## Contents

- [Quick start](#quick-start)
- [Verdicts and scoring](#verdicts-and-scoring)
- [Analysis layers](#analysis-layers)
- [What it detects](#what-it-detects)
- [Consequence engine](#consequence-engine)
- [GitHub Action](#github-action)
- [Command line](#command-line)
- [Configuration](#configuration)
- [Reports](#reports)
- [Limitations](#limitations)
- [Formal verification](#formal-verification)
- [Development](#development)
- [Documentation](#documentation)

## Quick start

Create `.github/workflows/payloadguard.yml`:

```yaml
name: PayloadGuard

on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  scan:
    name: PayloadGuard
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write       # posts the report as a PR comment

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0         # full history is required for the merge-base comparison

      - name: PayloadGuard scan
        id: payloadguard
        uses: PayloadGuard-PLG/payload-consequence-analyser@v1.6.0
        with:
          repo-token: ${{ secrets.GITHUB_TOKEN }}
          pr-description: ${{ github.event.pull_request.body }}

      - name: Apply verdict
        if: always()
        env:
          EXIT_CODE: ${{ steps.payloadguard.outputs.exit-code }}
        run: |
          if [ "$EXIT_CODE" = "2" ]; then echo "::error::DESTRUCTIVE verdict"; exit 2; fi
          if [ "$EXIT_CODE" = "1" ]; then echo "::error::analysis error"; exit 1; fi
```

Pin a release tag or a commit SHA. `@main` tracks changes that are not yet released ([`CHANGELOG.md`](CHANGELOG.md)).

To block merges, add the job (`PayloadGuard` above) under **Settings → Branches → Branch protection rules → Require status checks to pass before merging**.

Always pass `pr-description`. Without it the semantic layer cannot check the description, and a change that would otherwise be `SAFE` is reported as `REVIEW` (see [L5b](#analysis-layers)).

## Verdicts and scoring

Each layer contributes points; the total decides the verdict.

| Score | Verdict | Severity | Exit code |
|---|---|---|---|
| 0 | `SAFE` | LOW | `0` |
| 1–2 | `REVIEW` | MEDIUM | `0` |
| 3–4 | `CAUTION` | HIGH | `0` |
| 5 or more | `DESTRUCTIVE` | CRITICAL | `2` |

Exit code `1` means the analysis failed. Only `DESTRUCTIVE` fails a check by default.

| Signal | Points |
|---|---|
| Structural deletion severity CRITICAL (L4) | +5 |
| Security-critical file deleted (auth, security, permissions) | +5 |
| GitHub Actions poisoning, CRITICAL / HIGH signal (L2c) | +5 / +3 |
| AI tooling config poisoning, CRITICAL / HIGH signal (L2d) | +5 / +3 |
| Dependency not in `allowlist.yml` (L2b) | +3, once, however many packages |
| Critical-path file deleted (tests, CI and workflow files, Dockerfiles, dependency and build manifests, package `__init__.py`, core directories) | +2 |
| Added non-code file with CI triggers or shell execution patterns | +2 per match, at most +4 |
| Files deleted, lines deleted and deletion ratio (thresholds in [Configuration](#configuration)); the ratio counts from 100 deleted lines, or when a critical-path file is deleted | each 0–3; combined as the highest, +1 when two or more fire, at most +4 |
| Branch age: more than 90 / 180 / 365 days | +1 / +2 / +3 (see below) |

Rules that shape the result:

- **Branch age never decides `DESTRUCTIVE`.** It is applied after every other signal. It adds in full only when the other signals already total 5 or more; otherwise it raises the score to at most 4. An old branch can therefore reach `REVIEW` or `CAUTION` on age alone, but a `DESTRUCTIVE` verdict needs evidence from the change itself. The verdict reports `branch_age_score`.
- **Safety floors.** A deleted security-critical file, a CRITICAL structural result, or a CRITICAL Actions or AI-config signal is `DESTRUCTIVE` regardless of other signals.
- **Escalation after scoring.** The semantic layer (L5b) and the consequence policy (`advisory`, `enforce`) can raise a verdict. The raised verdict takes its own severity and recommendation, and the score rises to the lowest score of its band (1, 3 or 5); the JSON verdict reports the points added as `escalation_score`.
- The maximum score is 36.

## Analysis layers

| Layer | Function | Effect on the verdict |
|---|---|---|
| **L1 Surface** | File and line counts, permission changes, symlinks and submodules. | Counts feed L3; permission and symlink changes are reported. |
| **L2 Forensic** | Deleted critical-path and security-critical files; content scan of added non-code files for CI triggers and shell execution patterns. | Scored. |
| **L2b Dependencies** | Packages added to `requirements*.txt`, `pyproject.toml`, `package.json`, `go.mod` and `Cargo.toml`, checked against `allowlist.yml`. Runs only when `allowlist.yml` exists on the target branch. | Scored. |
| **L2c Actions poisoning** | Added or modified workflow files: base64 payloads, credential harvesting, dormant `workflow_dispatch` / `schedule` triggers that run shell commands (any YAML layout), forged bot authors, OIDC token elevation, typosquatted action consumers, `pull_request_target` misuse. | Scored. |
| **L2d AI config poisoning** | Added or modified AI tooling configuration: `.claude/settings.json`, `.gemini/settings.json`, `.cursor/rules/*.mdc`, `.vscode/tasks.json`, `package.json` lifecycle scripts, `composer.json`, `Gemfile`, `binding.gyp`, `mcp.json`. | Scored. |
| **L3 Consequence** | Combines the signals above into the score and verdict. | Decides the verdict. |
| **L4 Structural** | AST comparison: deleted classes, functions and constants, per file and across files. Fires when the deleted share reaches `thresholds.structural.deletion_ratio` and the count reaches `min_deleted_nodes`. Also reports McCabe complexity of newly added Python functions (advisory). | CRITICAL result scores +5. |
| **L5a Temporal** | Drift score from branch age and commit velocity on the target, classified `CURRENT` (below 250), `STALE` (250–1,000) or `DANGEROUS` (1,000 and above). | Reported. Branch age itself is scored in L3. |
| **L5b Semantic** | Heuristic comparison of the PR description with the diff profile (no LLM). Results: `TRANSPARENT`, `CAUTION_MISMATCH`, `DECEPTIVE_PAYLOAD`, `UNVERIFIED` (no description). | `UNVERIFIED` and `CAUTION_MISMATCH` raise `SAFE` to `REVIEW`. `DECEPTIVE_PAYLOAD` raises `SAFE` or `REVIEW` to `CAUTION`, and `CAUTION` to `DESTRUCTIVE` only when the content score alone is at least 3. |
| **L5c Runtime** | Optional eBPF agent for the CI runner: `execve`, outbound connections, `ptrace` and process-memory access, in audit or block mode with an egress allowlist. | Events are listed in the JSON report; no score. |
| **Consequence engine** | Differential detectors `D01`–`D10` ([below](#consequence-engine)). | Findings; verdict only in `advisory` or `enforce` mode. |

## What it detects

| Threat | Detector | Example | Policy |
|---|---|---|---|
| Mass deletion presented as a refactor | L1, L2, L4 | A long-lived branch described as a "minor syntax fix" deletes 60 files and 11,967 lines. | scored |
| Gutted functions | `D02` | A security or authentication method is reduced to `pass`, `...` or `return None`, in place or after a rename. | `BLOCK` |
| Distributed loss and threshold gaming | `D03` | One security function removed per file across five files; deleted methods padded with trivial getters. | `BLOCK` |
| Broken callers and API breaks | `D04` | An exported function is deleted or its required parameters change while callers, including aliased imports, still use the old contract. | `BLOCK` |
| Build wrapper tampering | `D05` | `curl … \| sh` or a reverse shell added to `mvnw`, `gradlew`, `Makefile` or `build.sh`. | `BLOCK` |
| Dependency drift | `D05` | A dependency is added to a manifest without a lockfile update. | `REVIEW` |
| Security guard regression | `D06` | `@require_auth` removed, `self._rollback()` dropped, `if not verify()` inverted, `and False` or `\|\| true` inserted. | `BLOCK` |
| Untrusted expression injection | `D08` | `${{ github.event.pull_request.title }}` interpolated into a `run:` block. | `BLOCK` |
| Pull request checkout with privileges | `D08` | `pull_request_target` combined with a checkout of the pull request head. | `BLOCK` |
| Action pin downgrade | `D08` | A 40-character commit SHA replaced by a tag or branch (`@v4`, `@main`). | `REVIEW` |
| CI gate weakening | `D08` | `continue-on-error: true` on required steps, or `permissions: write-all`. | `REVIEW` |
| Privileged artifact use | `D08` | A `workflow_run` workflow unpacks artifacts from an untrusted run. | `REVIEW` |
| Test assertion erosion | `D09` | Assertions replaced by `assert True` or `expect(true).toBe(true)`. | `BLOCK` |
| Newly skipped tests | `D09` | `@pytest.mark.skip`, `@pytest.mark.xfail`, `it.skip`, `pytest.skip()`, `t.Skip()`. | `REVIEW` |
| Data wipe-out | `D10` | A migration runs `TRUNCATE` or `DROP DATABASE` / `DROP SCHEMA`. | `BLOCK` |
| Irreversible schema drop | `D10` | A table or column is dropped with an empty or missing `downgrade()`, a Rails `change` drop, or Django `RunSQL` without `reverse_sql`. | `BLOCK` |
| Reversible schema drop | `D10` | A table or column is dropped in a forward migration that has a working rollback. | `REVIEW` |
| Workflow poisoning, OIDC theft | L2c | A workflow is changed to exfiltrate secrets, steal OIDC tokens or forge a CI identity. | scored |
| AI tooling config poisoning | L2d | A `SessionStart` hook or folder-open task in `.claude/settings.json` or `.vscode/tasks.json` runs a command. | scored |
| Deceptive PR description | L5b | The description says "minor copy fix"; the diff alters authentication or drops tables. | raises the verdict |

The policy column is each finding's recommendation. `Dxx` findings change the verdict and exit code only in `advisory` or `enforce` mode; the default is `shadow` ([Consequence modes](#consequence-modes)).

## Consequence engine

`consequence_engine.py` compares the symbols of the base and the head of the pull request. It parses Python, JavaScript (`.js`, `.jsx`, `.mjs`, `.cjs`), TypeScript (`.ts`, `.tsx`, `.mts`, `.cts`), Go, Rust and Java. Changed source in any other language is reported by `D01` as incomplete coverage; a missing parser is never read as absence of risk.

Symbols are matched in five stages:

1. **Exact:** same file, qualified name and kind.
2. **Renamed file:** same qualified name and kind in a file git reports as renamed.
3. **Cross-file move:** same qualified name, or same name with matching signature or body hash, in another changed file.
4. **Container and body-hash rename:** classes or structs matched by member overlap; functions renamed with an identical body hash and signature; same-scope replacement by a no-op stub.
5. **Residual:** unmatched symbols are `REMOVED` or `ADDED`.

Each symbol ends in one transition: `UNCHANGED`, `MODIFIED`, `GUTTED`, `MOVED`, `MOVED_AND_GUTTED`, `RENAMED`, `RENAMED_AND_GUTTED`, `AMBIGUOUS`, `REMOVED` or `ADDED`. A body counts as gutted when a non-stub symbol becomes a no-op stub, or when three or more statements with calls collapse to at most one statement without calls.

| Detector | Consequence classes | Policy |
|---|---|---|
| `D01_PARSER_INCOMPLETE` | `ANALYSIS_INCOMPLETE`: syntax errors, missing grammar, unsupported extension | `WARN` / `REVIEW` |
| `D02_BODY_WEAKENING` | `BODY_GUTTED`, `RENAME_WITH_BODY_WEAKENING`, `AMBIGUOUS_REFACTOR` | `BLOCK` / `WARN` |
| `D03_COMPOUND_LOSS` | `DISTRIBUTED_SYMBOL_LOSS`, `THRESHOLD_GAMING_DELETION` | `BLOCK` / `REVIEW` |
| `D04_PUBLIC_API_BREAK` | `UNRESOLVED_CALLER`, `PUBLIC_API_REMOVAL`, `PUBLIC_API_SIGNATURE_BREAK` | `BLOCK` / `REVIEW` |
| `D05_BUILD_DEPENDENCY_DELTA` | `BUILD_WRAPPER_TAMPERING`, `BUILD_SCRIPT_MODIFICATION`, `DEPENDENCY_LOCKFILE_MISMATCH` | `BLOCK` / `REVIEW` |
| `D06_GUARD_REGRESSION` | `SECURITY_GUARD_REMOVED`, `SECURITY_GUARD_WEAKENED` | `BLOCK` |
| `D08_WORKFLOW_INTEGRITY` | `UNTRUSTED_WORKFLOW_EXPRESSION_INJECTION`, `PULL_REQUEST_TARGET_UNTRUSTED_CHECKOUT`, `ACTION_PIN_DOWNGRADE`, `CI_GATE_WEAKENED`, `WORKFLOW_RUN_UNTRUSTED_ARTIFACT`, `ACTION_PIN_UNPINNED` | `BLOCK` / `REVIEW` / `WARN` |
| `D09_TEST_EROSION` | `TEST_ASSERTION_EROSION`, `TEST_SKIPPED_NEWLY` | `BLOCK` / `REVIEW` |
| `D10_MIGRATION_PERSISTENCE_LOSS` | `CATASTROPHIC_DATA_WIPEOUT`, `IRREVERSIBLE_PERSISTENCE_DROP`, `DESTRUCTIVE_PERSISTENCE_MIGRATION` | `BLOCK` / `REVIEW` |

Every finding carries the file, line, source snippet, affected symbols and a remediation.

### Consequence modes

| Mode | Behaviour |
|---|---|
| `shadow` *(default)* | All detectors run and their findings appear in the reports. The verdict and exit code are unchanged. |
| `advisory` | `BLOCK` and `REVIEW` findings are added to the verdict flags and raise a `SAFE` verdict to `REVIEW`. The exit code never becomes `2`. `WARN` findings are reported only. |
| `enforce` | Any `BLOCK` finding sets the verdict to `DESTRUCTIVE` (exit code `2`). `REVIEW` findings raise `SAFE` to `REVIEW`. |

Precedence: the `consequence-mode` input or `--consequence-mode`, then the `PAYLOADGUARD_CONSEQUENCE_MODE` environment variable, then `consequence.mode` in `payloadguard.yml`.

## GitHub Action

### Inputs

| Input | Default | Purpose |
|---|---|---|
| `repo-token` | `github.token` | Token for the PR comment. |
| `pr-description` | empty | Pull request body, for L5b. Pass `github.event.pull_request.body`. |
| `consequence-mode` | empty | `shadow`, `advisory` or `enforce`. Empty uses `payloadguard.yml`, then `shadow`. Any other value fails the step with exit code `1`. |
| `save-markdown` | `payloadguard-report.md` | File name of the Markdown report. |
| `app-id`, `private-key`, `installation-id` | empty | GitHub App credentials. When set, the result is also posted as a Check Run. |
| `auto-remediate` | `false` | Opens a new pull request that replaces mutable action tags with commit SHAs. Never commits to the scanned branch. Needs `pull-requests: write`. |
| `runtime-mode` | `disabled` | `audit` or `block` starts the eBPF agent on the runner (needs `CONFIG_KPROBES` and `CONFIG_FTRACE`; exits cleanly on unsupported kernels). Reads `payloadguard-policy.yaml` from the workspace. |

### Outputs

| Output | Value |
|---|---|
| `exit-code` | `0`, `1` or `2`. |
| `verdict` | `SAFE`, `REVIEW`, `CAUTION`, `DESTRUCTIVE`, or `ERROR` when the analysis failed. |
| `report-path`, `json-report-path` | Absolute paths of the Markdown and JSON reports. |
| `runtime-events-path` | `pg-runtime-events.json`, when `runtime-mode` is not `disabled`. |

The PR comment is created once and updated in place on each push.

### Enforcing a mode

```yaml
      - uses: PayloadGuard-PLG/payload-consequence-analyser@v1.6.0
        with:
          repo-token: ${{ secrets.GITHUB_TOKEN }}
          pr-description: ${{ github.event.pull_request.body }}
          consequence-mode: enforce
```

or in `payloadguard.yml` on the default branch:

```yaml
consequence:
  mode: enforce
```

### Trust boundary

`payloadguard.yml` and `allowlist.yml` are read from the **target branch**, not from the branch being scanned, so a pull request cannot change the policy its own scan runs under; edits take effect once merged. The `consequence-mode` input is only as trusted as the workflow file. On `pull_request` events that file comes from the pull request, so protect it with required workflows or CODEOWNERS.

The Action scans the pull request head commit, so pull requests from forks are scanned correctly.

## Command line

```bash
pip install payloadguard-plg     # Python 3.11 or later; installs the `payloadguard` command
```

or from source: `git clone https://github.com/PayloadGuard-PLG/payload-consequence-analyser.git && pip install -r requirements.txt`, then `python analyze.py`.

```bash
# analyse a branch against main
payloadguard . feature/my-branch main

# add the PR description for the semantic layer
payloadguard . feature/my-branch main --pr-description "Add profile endpoint and migrate session table"

# enforce consequence findings and write all report formats
payloadguard . feature/my-branch main --consequence-mode enforce \
    --save-json scan.json --save-markdown scan.md --save-sarif scan.sarif
```

Arguments: `repo_path`, `branch` (a branch name or commit), and optionally `target` (default `main`).

| Option | Purpose |
|---|---|
| `--pr-description TEXT` | PR description for L5b. |
| `--consequence-mode {shadow,advisory,enforce}` | Consequence policy. |
| `--save-json [PATH]` | JSON report (default `consequence_report.json`). |
| `--save-markdown [PATH]` | Markdown report (default `payloadguard-report.md`). |
| `--save-sarif [PATH]` | SARIF 2.1.0 report (default `payloadguard.sarif`). |

Exit codes: `0` for `SAFE`, `REVIEW` and `CAUTION`; `1` for an analysis error; `2` for `DESTRUCTIVE`. A command-line usage error (for example an invalid `--consequence-mode`) also exits `2`, as argparse does; check that the command is well-formed before treating `2` as a verdict.

## Configuration

`payloadguard.yml` is optional and read from the target branch. Every key is optional; the values shown are the defaults.

```yaml
consequence:
  enabled: true
  mode: shadow                        # shadow | advisory | enforce
  max_repo_files: 200                 # head files indexed to verify callers across files

thresholds:
  branch_age_days: [90, 180, 365]     # +1 / +2 / +3
  files_deleted:   [10, 20, 50]       # +1 / +2 / +3
  lines_deleted:   [5000, 10000, 50000]
  temporal:
    stale:     250.0                  # L5a drift score for STALE
    dangerous: 1000.0                 # L5a drift score for DANGEROUS
  structural:
    deletion_ratio:       0.20        # share of symbols deleted for CRITICAL
    min_deleted_nodes:    3
    complexity_threshold: 15          # McCabe advisory for new Python functions

sca:
  fail_on_unknown: true               # unlisted package adds +3 (needs allowlist.yml)

actions:
  enabled: true
  critical_signal_score: 5
  high_signal_score: 3
  trusted_oidc_consumers: []          # e.g. my-org/deploy-action

semantic:
  enabled: true
  micro_scope_churn_limit: 50
  insertion_ratio_fix_threshold: 0.9
```

[`examples/payloadguard.yml`](examples/payloadguard.yml) is a complete workflow that also posts a Check Run.

### Dependency allowlist (`allowlist.yml`)

L2b runs only when `allowlist.yml` exists in the repository root of the target branch. A package added to a manifest and absent from the list for its ecosystem adds +3.

```yaml
python:          # requirements*.txt, pyproject.toml
  - requests
npm:             # package.json
  - express
go:              # go.mod
  - github.com/spf13/cobra
rust:            # Cargo.toml
  - serde
```

## Reports

| Format | Produced by | Content |
|---|---|---|
| Console | CLI | Layer-by-layer summary, verdict and recommendation. |
| Markdown | Action, `--save-markdown` | PR comment; consequence findings in collapsible evidence and remediation sections. |
| JSON | Action, `--save-json` | Complete result: `verdict` (including `status`, `severity`, `severity_score`, `branch_age_score`, `escalation_score`, `flags`, `recommendation`), per-layer analysis, `consequence_analysis` (`consequence.v1`) and `runtime_events`. |
| SARIF 2.1.0 | CLI, `--save-sarif` | Consequence findings for GitHub code scanning; upload with `github/codeql-action/upload-sarif`. |
| Check Run | Action with GitHub App credentials | The Markdown report as a check on the pull request head commit. |

## Limitations

- **Structural coverage:** Python, JavaScript, TypeScript, Go, Rust and Java. Other source languages are reported as incomplete (`D01`), not analysed.
- **Shadow by default:** consequence findings do not change the verdict until `advisory` or `enforce` is set. The layers outside the consequence engine score in every mode.
- **Heuristics:** L5b and the content scans are pattern based. They raise the cost of hiding a payload; they do not prove intent. L5b needs a PR description to say anything.
- **History required:** the comparison needs the merge base, so the checkout must be a full clone (`fetch-depth: 0`). A single-branch clone or detached HEAD can raise a `BadName` error (open finding §2.3).
- **L5c** needs a Linux runner with BPF support and is advisory.

Open issues and their status are tracked in [`AUDIT_LOG.md`](AUDIT_LOG.md).

## Formal verification

The scoring rules are checked with three independent tools:

| Tool | Checks |
|---|---|
| **CrossHair** (symbolic execution) | Contracts on models of consequence scoring (C-01–C-15), structural drift (S1–S7), temporal drift (T1–T7) and semantic score bounds (M1–M9). |
| **Z3** (SMT) | Properties P1–P11 of the score-to-verdict mapping, including that branch age never decides `DESTRUCTIVE`. |
| **Dafny** | Machine-checked postconditions over the whole input domain for L3 (POST-1–12, POST-15/16), L4 (S1–S7) and L5a (T1–T8). Runs in CI on changes to `verification/dafny/`. |

What is verified is the transformation from signal values to a verdict, on models of the production functions; a test checks that the L3 model scores exactly as `analyze.py` does. Signal extraction (git, regular expressions, AST and YAML parsing), the consequence detectors and the escalation after L3 are covered by the test suite, not by these proofs. Results, run dates and environments: [`PROOFS.md`](PROOFS.md); specification and scope: [`VERIFICATION.md`](VERIFICATION.md), [`VERIFICATION_SPEC.md`](VERIFICATION_SPEC.md).

## Development

```bash
git clone https://github.com/PayloadGuard-PLG/payload-consequence-analyser.git
cd payload-consequence-analyser
pip install -r requirements.txt          # includes z3-solver and crosshair-tool
python -m pytest test_analyzer.py test_consequence_engine.py tests/ -q
```

Without `z3-solver` and `crosshair-tool` the proof tests skip and the rest pass. Latest run: [`TEST_REPORT.md`](TEST_REPORT.md).

Integration against real pull requests is in a separate repository, [`payloadguard-test-harness`](https://github.com/PayloadGuard-PLG/payloadguard-test-harness): fixture pull requests with expected verdicts, a manifest oracle and a mutation suite. A new detector needs positive and negative cases in [`test_consequence_engine.py`](test_consequence_engine.py).

## Documentation

| Document | Content |
|---|---|
| [`CHANGELOG.md`](CHANGELOG.md) | Changes per release. |
| [`WHITEPAPER.md`](WHITEPAPER.md) | Technical specification of every layer. |
| [`SYSTEM_BLUEPRINT.md`](SYSTEM_BLUEPRINT.md) | Repository structure, pipeline flow, module map. |
| [`VERIFICATION.md`](VERIFICATION.md), [`VERIFICATION_SPEC.md`](VERIFICATION_SPEC.md), [`PROOFS.md`](PROOFS.md) | Formal verification: contracts, specification, run records. |
| [`HARNESS_BLUEPRINT.md`](HARNESS_BLUEPRINT.md) | The integration test harness. |
| [`AUDIT_LOG.md`](AUDIT_LOG.md) | Findings register and incident reports. |
| [`DEVLOG.md`](DEVLOG.md) | Engineering log; earlier entries in [`docs/devlog/`](docs/devlog/). |
| [`llms.txt`](llms.txt) | Index for LLM tooling. |

PayloadGuard is maintained by [PayloadGuard-PLG](https://github.com/PayloadGuard-PLG). Licensed under [MIT](LICENSE).
