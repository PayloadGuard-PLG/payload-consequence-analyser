# PayloadGuard

[![PyPI](https://img.shields.io/pypi/v/payloadguard-plg.svg)](https://pypi.org/project/payloadguard-plg/)
[![Dafny Verification](https://github.com/PayloadGuard-PLG/payload-consequence-analyser/actions/workflows/verify-dafny.yml/badge.svg)](https://github.com/PayloadGuard-PLG/payload-consequence-analyser/actions/workflows/verify-dafny.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

PayloadGuard checks a pull request before it merges and reports whether the change would destroy, disable or hide something important. It runs as a GitHub Action or from the command line, compares the branch with its target using Git alone, and returns a verdict (`SAFE`, `REVIEW`, `CAUTION` or `DESTRUCTIVE`) with an exit code that branch protection can enforce.

It looks for changes that get past ordinary review and CI:

- a long-lived branch merged as a "minor fix" that deletes most of the code base;
- an authentication check removed, inverted, swallowed in a `try` block, or moved after the write it protects;
- tests whose assertions were replaced by tautologies, or that were skipped;
- migrations that drop data with no working rollback;
- workflows that run untrusted pull request input or exfiltrate secrets;
- build scripts, npm lifecycle scripts and AI tooling configuration that execute commands;
- a pull request description that understates what the diff does.

The analysis is deterministic and runs on the runner: no LLM, no external service, and the repository's code does not leave the machine.

## Contents

- [Quick start](#quick-start)
- [How a verdict is reached](#how-a-verdict-is-reached)
- [Policy modes](#policy-modes)
- [What it detects](#what-it-detects)
- [How it analyses a change](#how-it-analyses-a-change)
- [Configuration](#configuration)
- [GitHub Action reference](#github-action-reference)
- [Command line](#command-line)
- [Reports](#reports)
- [Limitations](#limitations)
- [Verification](#verification)
- [Development](#development)
- [Documentation](#documentation)

## Quick start

Add `.github/workflows/payloadguard.yml`:

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
          consequence-mode: advisory   # optional: shadow (default) | advisory | enforce

      - name: Apply verdict
        if: always()
        env:
          EXIT_CODE: ${{ steps.payloadguard.outputs.exit-code }}
        run: |
          if [ "$EXIT_CODE" = "2" ]; then echo "::error::DESTRUCTIVE verdict"; exit 2; fi
          if [ "$EXIT_CODE" = "1" ]; then echo "::error::analysis error"; exit 1; fi
```

Then:

1. **Block merges:** add the `PayloadGuard` check under **Settings → Branches → Branch protection rules → Require status checks to pass before merging**.
2. **Pin a version:** use a release tag or a commit SHA. `@main` includes changes not yet released (see [`CHANGELOG.md`](CHANGELOG.md), *Unreleased*).
3. **Pass the PR description:** without `pr-description` the description check cannot run, and a change that would otherwise be `SAFE` is reported as `REVIEW`.

Each run posts or updates one comment on the pull request with the verdict, the signals that produced it and the findings with their evidence.

## How a verdict is reached

| Verdict | Score | Severity | Exit code |
|---|---|---|---|
| `SAFE` | 0 | LOW | `0` |
| `REVIEW` | 1–2 | MEDIUM | `0` |
| `CAUTION` | 3–4 | HIGH | `0` |
| `DESTRUCTIVE` | 5 or more | CRITICAL | `2` |

Exit code `1` means the analysis failed. By default only `DESTRUCTIVE` fails the check.

PayloadGuard combines two kinds of analysis:

- **Scored checks** add points for evidence in the change. They apply in every mode.
- **Consequence detectors** (`D01`–`D10`) compare the code of the base and the head symbol by symbol and recommend `BLOCK`, `REVIEW` or `WARN`. Whether a recommendation changes the verdict depends on the [policy mode](#policy-modes).

| Scored signal | Points |
|---|---|
| Classes, functions or constants deleted beyond the structural thresholds | +5 |
| Security-critical file deleted (auth, security, permissions) | +5 |
| Poisoned GitHub Actions workflow: critical / high signal | +5 / +3 |
| Poisoned AI tooling configuration: critical / high signal | +5 / +3 |
| Dependency not in `allowlist.yml` | +3, once, however many packages |
| Critical-path file deleted (tests, CI and workflow files, Dockerfiles, dependency and build manifests, package `__init__.py`, core directories) | +2 |
| Added non-code file containing CI triggers or shell execution | +2 per match, at most +4 |
| Files deleted, lines deleted and deletion ratio (thresholds in [Configuration](#configuration)); the ratio counts from 100 deleted lines, or when a critical-path file is deleted | each 0–3; combined as the highest, +1 when two or more fire, at most +4 |
| Branch age above 90 / 180 / 365 days | +1 / +2 / +3 (see below) |

Rules that shape the result:

- **Branch age alone never makes a change `DESTRUCTIVE`.** Age is added after every other signal. It adds in full when the other signals already total 5 or more; otherwise it raises the score to at most 4.
- **Safety floors:** a deleted security-critical file, a critical structural deletion, or a critical workflow or AI-config signal is `DESTRUCTIVE` whatever else the change contains.
- **Raised verdicts:** the description check and the `advisory` and `enforce` modes can raise a verdict after scoring. The raised verdict takes its own severity and recommendation, and its score rises to the lowest score of its band (1, 3 or 5).

## Policy modes

| Mode | Effect of consequence detector findings |
|---|---|
| `shadow` *(default)* | Reported only. The verdict and exit code come from the scored checks. |
| `advisory` | `BLOCK` and `REVIEW` findings are added to the verdict flags and raise `SAFE` to `REVIEW`. The exit code never becomes `2`. |
| `enforce` | Any `BLOCK` finding makes the verdict `DESTRUCTIVE` (exit code `2`); `REVIEW` findings raise `SAFE` to `REVIEW`. |

`WARN` findings are reported in every mode and never change the verdict. `advisory` shows the detectors' results in the verdict without failing checks; `enforce` fails a check on any `BLOCK` finding.

Set the mode with the Action's `consequence-mode` input or `--consequence-mode`, the `PAYLOADGUARD_CONSEQUENCE_MODE` environment variable, or `consequence.mode` in `payloadguard.yml`, in that order of precedence.

## What it detects

| Area | What is reported | Check | Recommendation |
|---|---|---|---|
| **Deletion** | Mass deletion of files, lines or code symbols; a long-lived branch described as a small fix. | scored | — |
| | Security or authentication function reduced to `pass`, `...` or `return None`, in place or after a rename. | `D02` | `BLOCK` |
| | One security function removed per file across many files; deletions padded with trivial getters to stay under thresholds. | `D03` | `BLOCK` |
| | Source file replaced by a symlink to other code (the target is analysed). | `D02` | `REVIEW` |
| **Security guards** | Guard decorator removed, guard or rollback call dropped, condition inverted, `and False` / `\|\| true` inserted, unconditional early return. | `D06` | `BLOCK` |
| | Python: guard exception caught and ignored; guard made conditional or skippable by an earlier return; guard placed in a generator or lambda that never runs; a write moved ahead of the guard; a verifier called but its result ignored; a denial condition that now allows a case it denied (for example `or` changed to `and`). | `D06` | `BLOCK` |
| **APIs** | Exported function deleted, or its required parameters changed, while callers (including aliased imports) still use the old form. | `D04` | `BLOCK` / `REVIEW` |
| **Tests** | Assertions replaced by `assert True` or `expect(true).toBe(true)`. | `D09` | `BLOCK` |
| | Tests newly skipped (`@pytest.mark.skip`, `it.skip`, `t.Skip()`, …). | `D09` | `REVIEW` |
| **Migrations** | `TRUNCATE`, `DROP DATABASE` or `DROP SCHEMA`. | `D10` | `BLOCK` |
| | Table or column dropped without a working rollback. | `D10` | `BLOCK` |
| | Table or column dropped with a working rollback. | `D10` | `REVIEW` |
| **Build and dependencies** | `curl … \| sh`, a reverse shell or a binary payload added to or uncommented in `mvnw`, `gradlew`, `Makefile` or `build.sh`. | `D05` | `BLOCK` |
| | npm script that runs without being invoked (`preinstall`, `install`, `postinstall`, `dependencies`, `prepare`, `prepack`, `postpack`, `prepublish`, `prepublishOnly`, `publish`, `postpublish`) added or changed. | `D05` | `REVIEW` |
| | Dependency manifest changed without a lockfile update. | `D05` | `WARN` |
| | Package not on the allowlist. | scored | — |
| **CI workflows** | Untrusted expression such as `${{ github.event.pull_request.title }}` in a `run:` block; `pull_request_target` with a checkout of the PR head. | `D08` | `BLOCK` |
| | Action pinned to a SHA changed to a tag or branch; `continue-on-error: true` or `permissions: write-all`; `workflow_run` unpacking untrusted artifacts. | `D08` | `REVIEW` |
| | Secret exfiltration, cloud-metadata access, base64 payloads piped to a shell, OIDC token elevation, typosquatted actions, `pull_request_target` misuse, dormant `workflow_dispatch` / `schedule` triggers that run shell commands, forged bot authors. | scored | — |
| **AI tooling configuration** | Commands run by a `SessionStart` hook, a folder-open task, an npm or Composer lifecycle script, a Gemfile, `binding.gyp` or an MCP server definition; execute-imperatives in always-applied Cursor rules; hidden Unicode characters. | scored | — |
| **PR description** | A description that claims a small or documentation-only change for a diff that is large, adds new declarations, touches files of many types or alters sensitive files it does not name. | scored (raises the verdict) | — |

A file renamed or copied into a workflow, AI-config, build-script, dependency-manifest or migration path from a path that is not checked is treated as newly added there.

## How it analyses a change

| Stage | What it does |
|---|---|
| Surface | File and line counts, permission changes, symlinks and submodules. |
| Forensic | Deleted critical-path and security-critical files; content of added non-code files. |
| Dependencies | Packages added to `requirements*.txt`, `pyproject.toml`, `package.json`, `go.mod` and `Cargo.toml`, checked against `allowlist.yml` (only when the file exists on the target branch). `package.json` is read as JSON: entries added or changed in `dependencies`, `devDependencies`, `peerDependencies`, `optionalDependencies`, `overrides` and `resolutions`. |
| Workflows | Workflow files, scanned for the patterns in the table above; triggers are read from the parsed YAML. |
| AI tooling configuration | `.claude/settings.json`, `.gemini/settings.json`, `.cursor/rules/*.mdc`, `.vscode/tasks.json`, `package.json` lifecycle scripts, `composer.json`, `Gemfile`, `binding.gyp`, `mcp.json`. |
| Structure | Deleted classes, functions and constants per file and across files; complexity of new Python functions (advisory). |
| Branch drift | Branch age and commit velocity on the target, classified `CURRENT`, `STALE` or `DANGEROUS` (reported; age itself is scored). |
| Description | Compares the PR description with the diff. It flags only descriptions that claim a small change ("minor", "typo", "trivial", …) or a documentation change ("docs", "readme", "changelog"; then only the files outside documentation are measured). A description that announces a large change ("major", "overhaul", "rewrite", …) gets a review advisory. Results: `TRANSPARENT`, `CAUTION_MISMATCH` (raises `SAFE` to `REVIEW`), `DECEPTIVE_PAYLOAD` (raises `SAFE` or `REVIEW` to `CAUTION`, and `CAUTION` to `DESTRUCTIVE` only when the change alone scores at least 3), `UNVERIFIED` (no description; raises `SAFE` to `REVIEW`). |
| Consequence engine | Parses base and head, matches each symbol across renames and moves, and runs detectors `D01`–`D10`. |
| Runtime (optional) | eBPF agent on the CI runner recording process starts, outbound connections, `ptrace` and process-memory access, in audit or block mode with an egress allowlist. Reported, not scored. |

The consequence engine parses Python, JavaScript (`.js`, `.jsx`, `.mjs`, `.cjs`), TypeScript (`.ts`, `.tsx`, `.mts`, `.cts`), Go, Rust and Java:

- **Coverage is reported.** Changed source in other languages, files that do not parse, invalid encodings and symlinks that point outside the repository are reported by `D01` as incomplete analysis; a missing parser is never read as absence of risk.
- **Symlinks** are resolved inside the repository and analysed as the content they point to.
- **Callers across files:** files that mention a changed symbol are indexed first, then other files, up to `max_repo_files`. The report states how many source files the index covered, and an API finding that found no breaking caller says when coverage was incomplete.

| Detector | Consequence classes | Recommendation |
|---|---|---|
| `D01_PARSER_INCOMPLETE` | `ANALYSIS_INCOMPLETE` | `WARN` / `REVIEW` |
| `D02_BODY_WEAKENING` | `BODY_GUTTED`, `RENAME_WITH_BODY_WEAKENING`, `AMBIGUOUS_REFACTOR` | `BLOCK` / `WARN` |
| `D02_STRUCTURAL_DELTA` | `SOURCE_REPLACED_BY_SYMLINK` | `REVIEW` |
| `D03_COMPOUND_LOSS` | `DISTRIBUTED_SYMBOL_LOSS`, `THRESHOLD_GAMING_DELETION` | `BLOCK` / `REVIEW` |
| `D04_PUBLIC_API_BREAK` | `UNRESOLVED_CALLER`, `PUBLIC_API_REMOVAL`, `PUBLIC_API_SIGNATURE_BREAK` | `BLOCK` / `REVIEW` / `WARN` |
| `D05_BUILD_DEPENDENCY_DELTA` | `BUILD_WRAPPER_TAMPERING`, `BUILD_SCRIPT_MODIFICATION`, `DEPENDENCY_LOCKFILE_MISMATCH` | `BLOCK` / `REVIEW` / `WARN` |
| `D06_GUARD_REGRESSION` | `SECURITY_GUARD_REMOVED`, `SECURITY_GUARD_WEAKENED` | `BLOCK` |
| `D08_WORKFLOW_INTEGRITY` | `UNTRUSTED_WORKFLOW_EXPRESSION_INJECTION`, `PULL_REQUEST_TARGET_UNTRUSTED_CHECKOUT`, `ACTION_PIN_DOWNGRADE`, `CI_GATE_WEAKENED`, `WORKFLOW_RUN_UNTRUSTED_ARTIFACT`, `ACTION_PIN_UNPINNED` | `BLOCK` / `REVIEW` / `WARN` |
| `D09_TEST_EROSION` | `TEST_ASSERTION_EROSION`, `TEST_SKIPPED_NEWLY` | `BLOCK` / `REVIEW` |
| `D10_MIGRATION_PERSISTENCE_LOSS` | `CATASTROPHIC_DATA_WIPEOUT`, `IRREVERSIBLE_PERSISTENCE_DROP`, `DESTRUCTIVE_PERSISTENCE_MIGRATION` | `BLOCK` / `REVIEW` |

Every finding carries the file, line, affected symbols, evidence and a remediation. [`WHITEPAPER.md`](WHITEPAPER.md) describes each stage and detector in detail.

## Configuration

`payloadguard.yml` is optional and read from the **target branch**. Every key is optional; the values shown are the defaults.

```yaml
consequence:
  enabled: true
  mode: shadow                        # shadow | advisory | enforce
  max_repo_files: 200                 # head files indexed to find callers of changed code

thresholds:
  branch_age_days: [90, 180, 365]     # +1 / +2 / +3
  files_deleted:   [10, 20, 50]       # +1 / +2 / +3
  lines_deleted:   [5000, 10000, 50000]
  temporal:
    stale:     250.0                  # drift score for STALE
    dangerous: 1000.0                 # drift score for DANGEROUS
  structural:
    deletion_ratio:       0.20        # share of symbols deleted for a critical result
    min_deleted_nodes:    3
    complexity_threshold: 15          # complexity advisory for new Python functions

sca:
  fail_on_unknown: true               # unlisted package adds +3 (needs allowlist.yml)

actions:
  enabled: true
  critical_signal_score: 5
  high_signal_score: 3
  trusted_oidc_consumers: []          # e.g. my-org/deploy-action

semantic:
  enabled: true
  micro_scope_churn_limit: 50         # lines a "small change" claim may cover
  insertion_ratio_fix_threshold: 0.9  # share of additions that makes a small "fix" suspicious
```

### Dependency allowlist (`allowlist.yml`)

The dependency check runs only when `allowlist.yml` exists in the repository root of the target branch. A package added to a manifest and absent from the list for its ecosystem adds +3.

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

### Trust boundary

`payloadguard.yml` and `allowlist.yml` are read from the target branch, so a pull request cannot change the policy its own scan runs under; edits take effect once merged. The `consequence-mode` input is only as trusted as the workflow file, which on `pull_request` events comes from the pull request itself: protect it with required workflows or CODEOWNERS. The Action scans the pull request's head commit, so pull requests from forks are scanned correctly.

## GitHub Action reference

### Inputs

| Input | Default | Purpose |
|---|---|---|
| `repo-token` | `github.token` | Token for the PR comment. |
| `pr-description` | empty | Pull request body for the description check. Pass `github.event.pull_request.body`. |
| `consequence-mode` | empty | `shadow`, `advisory` or `enforce`. Empty uses `payloadguard.yml`, then `shadow`. Any other value fails the step with exit code `1`. |
| `save-markdown` | `payloadguard-report.md` | File name of the Markdown report. |
| `app-id`, `private-key`, `installation-id` | empty | GitHub App credentials. When set, the result is also posted as a Check Run. |
| `auto-remediate` | `false` | Opens a separate pull request that replaces mutable action tags with commit SHAs. Never commits to the scanned branch. Needs `pull-requests: write`. |
| `runtime-mode` | `disabled` | `audit` or `block` starts the eBPF agent (needs `CONFIG_KPROBES` and `CONFIG_FTRACE`; exits cleanly on unsupported kernels). Reads `payloadguard-policy.yaml` from the workspace. |

### Outputs

| Output | Value |
|---|---|
| `exit-code` | `0`, `1` or `2`. |
| `verdict` | `SAFE`, `REVIEW`, `CAUTION`, `DESTRUCTIVE`, or `ERROR` when the analysis failed. |
| `report-path`, `json-report-path` | Absolute paths of the Markdown and JSON reports. |
| `runtime-events-path` | `pg-runtime-events.json`, when `runtime-mode` is not `disabled`. |

[`examples/payloadguard.yml`](examples/payloadguard.yml) is a complete workflow that also posts a Check Run.

## Command line

```bash
pip install payloadguard-plg     # Python 3.11 or later; installs the `payloadguard` command
```

or from source: `git clone https://github.com/PayloadGuard-PLG/payload-consequence-analyser.git && pip install -r requirements.txt`, then `python analyze.py`.

```bash
# analyse a branch against main
payloadguard . feature/my-branch main

# include the PR description
payloadguard . feature/my-branch main --pr-description "Add profile endpoint and migrate session table"

# apply consequence findings and write every report format
payloadguard . feature/my-branch main --consequence-mode enforce \
    --save-json scan.json --save-markdown scan.md --save-sarif scan.sarif
```

Arguments: `repo_path`, `branch` (a branch name or commit) and optionally `target` (default `main`).

| Option | Purpose |
|---|---|
| `--pr-description TEXT` | PR description for the description check. |
| `--consequence-mode {shadow,advisory,enforce}` | Policy mode. |
| `--save-json [PATH]` | JSON report (default `consequence_report.json`). |
| `--save-markdown [PATH]` | Markdown report (default `payloadguard-report.md`). |
| `--save-sarif [PATH]` | SARIF 2.1.0 report (default `payloadguard.sarif`). |

Exit codes: `0` for `SAFE`, `REVIEW` and `CAUTION`; `1` for an analysis error; `2` for `DESTRUCTIVE`. A usage error (for example an invalid `--consequence-mode`) also exits `2`, as argparse does, so check the command is well formed before treating `2` as a verdict.

## Reports

| Format | Produced by | Content |
|---|---|---|
| Console | CLI | Summary per analysis stage, verdict and recommendation. |
| Markdown | Action, `--save-markdown` | PR comment, with each finding's evidence and remediation in a collapsible section. |
| JSON | Action, `--save-json` | Complete result: the verdict (`status`, `severity`, `severity_score`, `branch_age_score`, `escalation_score`, `flags`, `recommendation`), each stage's results, the consequence analysis (`consequence.v1`: findings, parser completeness, caller-index coverage) and runtime events. |
| SARIF 2.1.0 | CLI, `--save-sarif` | Consequence findings for GitHub code scanning; upload with `github/codeql-action/upload-sarif`. |
| Check Run | Action with GitHub App credentials | The Markdown report as a check on the pull request's head commit. |

## Limitations

- **Languages:** the consequence engine parses Python, JavaScript, TypeScript, Go, Rust and Java; other languages are reported as incompletely analysed. The guard checks for swallowed, reordered, conditional, deferred and ignored guards and for weakened denial conditions are available for Python only.
- **No dataflow analysis:** values are not followed between statements, so request data reaching a SQL string is not detected, and an `assert` used as a guard counts as enforced although `python -O` removes it.
- **Shadow by default:** consequence findings change the verdict only in `advisory` or `enforce` mode. The scored checks apply in every mode.
- **Heuristics:** the description check and the content scans are pattern based. They make hiding a payload harder; they do not prove intent, and the description check needs a description.
- **Full history:** the comparison needs the merge base, so check out with `fetch-depth: 0`. A single-branch clone or a detached HEAD can fail with a `BadName` error.
- **Runtime agent:** needs a Linux runner with BPF support and is advisory.

Known issues are tracked in [`AUDIT_LOG.md`](AUDIT_LOG.md).

## Verification

The mapping from signals to verdict is checked with three independent tools: CrossHair contracts and Z3 properties on models of the scoring functions, and Dafny proofs of the scoring, structural and drift rules over their whole input domain. Tests confirm that the models of the scoring and of the description check score as the production code does. Signal extraction (Git, parsing, pattern matching) and the consequence detectors are covered by the test suite and the [test harness](https://github.com/PayloadGuard-PLG/payloadguard-test-harness), not by the proofs. Details: [`VERIFICATION.md`](VERIFICATION.md); run records: [`PROOFS.md`](PROOFS.md).

## Development

```bash
git clone https://github.com/PayloadGuard-PLG/payload-consequence-analyser.git
cd payload-consequence-analyser
pip install -r requirements.txt          # includes z3-solver and crosshair-tool
python -m pytest test_analyzer.py test_consequence_engine.py tests/ -q
```

Without `z3-solver` and `crosshair-tool` the proof tests are skipped and the rest run.

End-to-end behaviour on real pull requests is tested in [`payloadguard-test-harness`](https://github.com/PayloadGuard-PLG/payloadguard-test-harness): fixture pull requests with expected verdicts, a manifest oracle and a mutation suite. A new detector needs positive and negative cases in [`test_consequence_engine.py`](test_consequence_engine.py).

## Documentation

| Document | Content |
|---|---|
| [`CHANGELOG.md`](CHANGELOG.md) | Changes per release. |
| [`WHITEPAPER.md`](WHITEPAPER.md) | Technical specification of every stage and detector. |
| [`SYSTEM_BLUEPRINT.md`](SYSTEM_BLUEPRINT.md) | Repository structure, pipeline flow, module map. |
| [`VERIFICATION.md`](VERIFICATION.md), [`VERIFICATION_SPEC.md`](VERIFICATION_SPEC.md), [`PROOFS.md`](PROOFS.md) | Formal verification: contracts, specification, run records. |
| [`HARNESS_BLUEPRINT.md`](HARNESS_BLUEPRINT.md) | The integration test harness. |
| [`AUDIT_LOG.md`](AUDIT_LOG.md) | Findings register. |
| [`DEVLOG.md`](DEVLOG.md) | Engineering log. |
| [`llms.txt`](llms.txt) | Index for LLM tooling. |

PayloadGuard is maintained by [PayloadGuard-PLG](https://github.com/PayloadGuard-PLG) and licensed under [MIT](LICENSE).
