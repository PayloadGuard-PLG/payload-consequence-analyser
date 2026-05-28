# PayloadGuard

**Version:** 1.2.0 &nbsp;|&nbsp; **Status:** Production &nbsp;|&nbsp; **Released:** May 2026 &nbsp;|&nbsp; **Runtime Agent:** Verified on WSL2 / Ubuntu 22.04+ &nbsp;|&nbsp; **Formally Verified:** CrossHair · Z3 SMT · Dafny — [details](#formal-verification)

PayloadGuard is a static and runtime analysis tool for pull requests. It scans the full diff before a merge and produces a forensic verdict on the risk of the changeset — catching destructive, deceptive, or malicious contributions that code review alone is likely to miss. An optional eBPF runtime agent fires alongside the static scan on the Actions runner, auditing or blocking suspicious process behaviour at kernel level.

It was built in response to a specific class of incident: a branch held open for months, submitted under a harmless description, containing a diff that would delete tens of thousands of lines and wipe an entire application architecture in a single merge. PayloadGuard makes that class of attack detectable before it reaches main.

---

## What it detects

PayloadGuard analyses nine dimensions of risk across every PR:

| Layer | What it examines |
|---|---|
| L1 — Surface | File and line counts, deletion ratios, binary files, permission changes, symlinks |
| L2 — Forensic | Critical-path deletions, security-sensitive file removal, added file content (CI triggers, shell execution) |
| L2b — SCA | Package manifest diffs scanned against an allowlist for unverified dependencies (opt-in) |
| L2c — Actions Poisoning | Added and modified workflow files scanned for base64 payload delivery, credential harvesting, dormant triggers, forged bot identity, OIDC privilege escalation, and unsafe pull_request_target usage |
| L3 — Consequence Model | Weighted scoring across all signals, producing a single verdict |
| L4 — Structural Drift | AST-level diff: which named classes, functions, and constants were actually removed |
| L5a — Temporal Drift | Branch age multiplied by target repo velocity — a quantified measure of semantic divergence |
| L5b — Semantic Transparency | Whether the PR description matches what the diff actually does |
| L5c — Runtime Agent | eBPF tracepoint agent (audit/block mode): execve, egress connect, ptrace, /proc/mem — fires on the runner alongside the static scan. Advisory; no score impact. Requires kernel ≥5.8 with `CONFIG_KPROBES=y`. |

Verdicts: **SAFE** · **REVIEW** · **CAUTION** · **DESTRUCTIVE**

DESTRUCTIVE verdicts can be wired to block the merge button via a branch protection rule.

---

## Installation

### GitHub Action (recommended)

Add `.github/workflows/payloadguard.yml` to your repository:

```yaml
name: PayloadGuard

on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: PayloadGuard Scan
        id: payloadguard
        uses: PayloadGuard-PLG/payload-consequence-analyser@main
        with:
          repo-token: ${{ secrets.GITHUB_TOKEN }}
          pr-description: ${{ github.event.pull_request.body }}

      - name: Enforce verdict
        if: always()
        env:
          EXIT_CODE: ${{ steps.payloadguard.outputs.exit-code }}
        run: |
          if [ "$EXIT_CODE" = "1" ]; then exit 1; fi
          if [ "$EXIT_CODE" = "2" ]; then exit 2; fi
```

Set the `scan` job as a required status check in your branch protection rules. Any PR that returns DESTRUCTIVE will fail the check and cannot be merged until the issues are resolved.

### Python package

```bash
pip install payloadguard-plg
```

### From source

```bash
git clone https://github.com/PayloadGuard-PLG/payload-consequence-analyser.git
pip install -r requirements.txt
```

**Requirements:** Python 3.8+. Core dependencies: GitPython, PyYAML, PyJWT, requests. Layer 4 multi-language structural analysis requires tree-sitter grammar packages (included in `requirements.txt`). Files for languages whose grammars are not installed are skipped silently.

---

## CLI usage

```bash
python analyze.py <repo_path> <branch> [target_branch]
```

```bash
# Scan a branch against main
python analyze.py . feature/auth-refactor main

# Include the PR description for semantic analysis (recommended)
python analyze.py . feature/auth-refactor main \
  --pr-description "Refactor authentication module"

# Output a JSON report
python analyze.py . feature/auth-refactor main --save-json

# Output a Markdown report
python analyze.py . feature/auth-refactor main \
  --save-markdown reports/scan.md
```

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | SAFE, REVIEW, or CAUTION — proceed |
| `1` | Analysis error |
| `2` | DESTRUCTIVE — do not merge |

Wire exit code `2` to your CI enforcement step to block merges automatically.

---

## The report

Every scan produces a structured report covering each layer. Below is a reference for what each section means.

### Temporal

Branch age and the commits being compared. A long-lived branch represents a semantic gap — the further it has diverged from target, the higher the risk that the diff has become meaningless or actively dangerous in context.

```
📅 TEMPORAL
   Branch age: 14 days
   Branch commit: a1b2c3d (2026-04-08)
   Target commit: e4f5g6h (2026-04-22)

   Branch is current — no staleness risk.
```

### File changes

Raw scope of the changeset. Deletion count is the primary signal — a PR that adds two files and deletes forty is not a normal PR.

```
📁 FILE CHANGES
   Added:      3
   Deleted:    1
   Modified:   5
   Total:      9
```

### Line changes

Volume and direction of change. The deletion ratio measures what fraction of total churn is removal. Above 50% is notable; above 90% means the PR is removing almost everything it touches.

> The deletion ratio threshold only activates when at least 100 lines are deleted. Small PRs are not penalised for high ratios.

```
📝 LINE CHANGES
   Added:          420
   Deleted:         18
   Net:           +402
   Deletion ratio:  4.1%
```

### Structural drift (Layer 4)

Parses every modified source file and identifies which named classes, functions, and constants were removed. This catches the case where a file is described as "modified" but has been gutted — line-level diffs do not reveal that `AuthManager` no longer exists.

Structural CRITICAL requires both conditions: deletion ratio above threshold **and** a minimum number of nodes removed. The dual gate prevents false positives on small utility files.

**Supported languages:** Python · JavaScript · TypeScript · Go · Rust · Java

```
🧬 STRUCTURAL DRIFT (Layer 4)
   Overall severity: CRITICAL
   src/core/auth.py: 8 nodes deleted (80.0%) [CRITICAL]
      Removed: AuthManager, SessionStore, TokenValidator, SECRET_KEY
```

### GitHub Actions poisoning (Layer 2c)

Scans every added or modified `.github/workflows/` file for workflow poisoning signals. These are distinct from generic shell patterns — they target the specific techniques used to poison CI pipelines while evading superficial review.

**Signal types:**

| Signal | Severity | Description |
|---|---|---|
| `base64_payload` | CRITICAL | Base64-encoded content piped to a shell interpreter |
| `credential_harvest` | CRITICAL | Environment variable exfiltration, cloud metadata endpoint probing, secret grep |
| `pull_request_target_with_write_permissions` | CRITICAL | `pull_request_target` trigger combined with write permissions — enables pwn-request attacks |
| `dormant_trigger_with_payload` | HIGH | `workflow_dispatch` or `schedule` trigger combined with shell execution — hidden activation path |
| `forged_bot_author` | HIGH | Git identity configured to impersonate a known bot or automation account |
| `oidc_elevation_no_consumer` | HIGH | `id-token: write` permission granted with no recognised OIDC consumer action present |
| `dangerous_trigger_pull_request_target` | HIGH | `pull_request_target` trigger without write permissions — elevated risk, requires review |

CRITICAL signals score +5 (immediate DESTRUCTIVE threshold). HIGH signals score +3.

Detection is hardened against three common bypass techniques: YAML folded/literal block scalar splitting (multi-line base64 obfuscation), OIDC consumer typosquatting (exact-match allowlist, not prefix matching), and two-tier `pull_request_target` scoring based on declared permissions.

```
🎯 GITHUB ACTIONS POISONING (Layer 2c)
   1 workflow(s) flagged

   File                                  Signal types        Severity
   .github/workflows/deployment.yml      credential_harvest  CRITICAL
```

### Temporal drift (Layer 5a)

Compound staleness score: `branch_age_days × target_commits_per_day`. Raw branch age is a weak signal on a slow-moving repository; on a high-velocity codebase a 90-day branch represents a substantial semantic gap.

| Status | Score | Interpretation |
|---|---|---|
| CURRENT | < 250 | Branch context is valid |
| STALE | 250–999 | Significant divergence — review diff carefully |
| DANGEROUS | ≥ 1000 | Rebase required before this is viable |

### Semantic transparency (Layer 5b)

Compares the PR description against the actual diff profile using a three-phase heuristic engine: Linguistic Lexer → Diff Profiler → Cross-Correlation Matrix. Derives an `mci_score ∈ [0,1]` from five independent signals.

| Status | Meaning |
|---|---|
| `TRANSPARENT` | Description accurately reflects the diff scope and operation type |
| `UNVERIFIED` | No description provided |
| `CAUTION_MISMATCH` | Partial inconsistency — mci_score > 0 or macro-scope advisory |
| `DECEPTIVE_PAYLOAD` | High-confidence mismatch — mci_score ≥ 0.5 — escalates verdict |

**Signals:**

| Signal | Trigger | MCI |
|---|---|---|
| `scope_understated` | Micro-scope language ("minor", "typo", "cleanup") with total churn > 50 lines | +0.4 |
| `operation_mutation` | Micro-scope language with structural additions (new functions or classes) in diff | +0.3 |
| `hidden_component_modification` | Sensitive file (auth, workflow, manifest, Dockerfile, schema) in diff not named in description | +0.3 |
| `phantom_additions` | Remedial claim ("fix", "patch", "resolve") with insertion ratio > 90% | +0.4 |
| `cross_stack_micro_claim` | Micro-scope language touching ≥ 3 distinct file types | +0.2 |
| `macro_scope_manual_review` | Macro-scope language ("overhaul", "architectural", "rewrite", "comprehensive") — advisory only | none |

`DECEPTIVE_PAYLOAD` escalates the verdict one step (SAFE→CAUTION, REVIEW→CAUTION, CAUTION→DESTRUCTIVE). `CAUTION_MISMATCH` escalates SAFE→REVIEW only. No description (`UNVERIFIED`) escalates SAFE→REVIEW.

---

## Configuration

Place `payloadguard.yml` in your repository root to override defaults. All fields are optional.

```yaml
thresholds:
  branch_age_days: [90, 180, 365]       # Score increases at each tier
  files_deleted:   [10, 20, 50]
  lines_deleted:   [5000, 10000, 50000]
  temporal:
    stale:     250
    dangerous: 1000
  structural:
    deletion_ratio:    0.20             # Fraction of AST nodes removed
    min_deleted_nodes: 3               # Both conditions must be met for CRITICAL

sca:
  fail_on_unknown: true                 # Treat unrecognised packages as CAUTION

actions:
  enabled: true
  critical_signal_score: 5
  high_signal_score: 3
  trusted_oidc_consumers:              # Extend the built-in OIDC allowlist
    - my-org/custom-deploy-action

semantic:
  micro_scope_churn_limit: 50          # V_s: churn threshold for micro-scope mismatch
  insertion_ratio_fix_threshold: 0.9   # V_r: insertion ratio for phantom additions
```

### SCA (Layer 2b)

To enable dependency scanning, create `allowlist.yml` in your repository root listing approved packages. Any package appearing in a manifest diff (`requirements.txt`, `package.json`, `go.mod`, `Cargo.toml`, `Gemfile`) that is not on the allowlist scores +3 per unique package.

```yaml
# allowlist.yml
packages:
  - requests
  - numpy
  - django
```

---

## GitHub App

To post a named check run in the PR checks tab (in addition to the sticky PR comment), register a GitHub App and configure three repository secrets:

| Secret | Value |
|---|---|
| `PAYLOADGUARD_APP_ID` | App ID from the GitHub App settings page |
| `PAYLOADGUARD_PRIVATE_KEY` | Contents of the RSA private key file (PEM format) |
| `PAYLOADGUARD_INSTALLATION_ID` | Installation ID from `github.com/settings/installations` |

Pass these to the action:

```yaml
      - name: PayloadGuard Scan
        uses: PayloadGuard-PLG/payload-consequence-analyser@main
        with:
          repo-token: ${{ secrets.GITHUB_TOKEN }}
          pr-description: ${{ github.event.pull_request.body }}
          app-id: ${{ secrets.PAYLOADGUARD_APP_ID }}
          private-key: ${{ secrets.PAYLOADGUARD_PRIVATE_KEY }}
          installation-id: ${{ secrets.PAYLOADGUARD_INSTALLATION_ID }}
```

Without the App secrets the step is a no-op. The PR comment and merge enforcement continue to function.

---

## Scoring reference

The consequence model (Layer 3) accumulates a weighted score across all signals and maps it to a verdict.

### Score contributions

| Signal | Condition | Points |
|---|---|---|
| Branch age | > 90 / > 180 / > 365 days | +1 / +2 / +3 |
| Files deleted | > 10 / > 20 / > 50 | +1 / +2 / +3 |
| Deletion ratio | > 50% / > 70% / > 90% | +1 / +2 / +3 |
| Lines deleted | > 5k / > 10k / > 50k | +1 / +2 / +3 |
| Critical path files deleted | > 0 / > 5 | +1 / +2 |
| Security files deleted | any | +5 |
| Structural severity CRITICAL | | +3 |
| Unverified dependency (SCA) | per unique package | +3 |
| Added file content: shell or CI patterns | | +2 per match |
| Actions poisoning CRITICAL signal | | +5 |
| Actions poisoning HIGH signal | | +3 |

The three deletion dimensions (files, ratio, lines) are correlated. To prevent compounding, they are scored independently and capped: `min(4, max(files, ratio, lines) + 1 if ≥2 non-zero)`.

### Verdict thresholds

| Score | Verdict | Severity |
|---|---|---|
| 0 | SAFE | LOW |
| 1–2 | REVIEW | MEDIUM |
| 3–4 | CAUTION | HIGH |
| ≥ 5 | DESTRUCTIVE | CRITICAL |

---

## The incident

In April 2026 a developer received a Codex suggestion described as a *"minor syntax fix"*. The branch had been open for ten months. The diff would have deleted 60 files, 11,967 lines, 217 tests, and the entire application architecture in a single merge. No individual reviewer caught it before it was stopped at the last moment.

The forensic report PayloadGuard would have produced on that branch:

```
======================================================================
PAYLOADGUARD ANALYSIS: codex-suggestion → main
======================================================================

📅 TEMPORAL
   Branch age: 312 days
   Branch commit: fa3c21d (2025-06-04)
   Target commit: b87e90a (2026-04-22)

📁 FILE CHANGES
   Added:       2   Deleted:  61   Modified:   4   Total: 67

   61 files deleted — DESTRUCTIVE threshold exceeded (>50).

📝 LINE CHANGES
   Added:       214   Deleted: 11,967   Net: -11,753
   Deletion ratio: 98.2%

   98.2% deletion ratio — almost the entire changeset is removal.

🧬 STRUCTURAL DRIFT (Layer 4)
   Overall severity: CRITICAL
   src/core/auth.py: 12 nodes deleted (94.0%) [CRITICAL]
      Removed: AuthManager, SessionStore, TokenValidator,
               PermissionGate, RoleRegistry

⏱  TEMPORAL DRIFT (Layer 5a)
   Status: DANGEROUS   Drift score: 3120.0
   Target velocity: 10.0 commits/day

🔎 SEMANTIC TRANSPARENCY (Layer 5b) — DECEPTIVE_PAYLOAD
   MCI score: 0.700
   Signals:   scope_understated, operation_mutation
   ❌ DO NOT MERGE. PR description is inconsistent with actual diff scope and structure.

🔍 VERDICT: DESTRUCTIVE [CRITICAL]
   ❌ DO NOT MERGE — This would catastrophically alter the codebase

   Flags:
   ⚠  Branch is 312 days old
   ⚠  61 files deleted (massive scope)
   ⚠  98.2% deletion ratio
   ⚠  Structural drift CRITICAL — core authentication layer removed
   ⚠  11,967 lines deleted
   ⚠  5 critical-path files deleted
   ⚠  Description contradicts actual severity

======================================================================
```

Every signal was present and quantifiable. This tool makes them visible before the merge button is pressed.

---

## Supported languages (Layer 4)

| Language | Parser | Tracked constructs |
|---|---|---|
| Python | stdlib `ast` | Functions, classes, async functions, module-level assignments, annotated assignments |
| JavaScript / JSX | tree-sitter | Functions, classes, arrow functions, variable declarators |
| TypeScript / TSX | tree-sitter | Functions, classes, interfaces, type aliases, enums |
| Go | tree-sitter | Functions, methods, type specs, const specs |
| Rust | tree-sitter | Functions, structs, enums, traits, const and static items |
| Java | tree-sitter | Methods, classes, interfaces, enums |

Files in languages without an installed grammar are skipped. Other file types contribute to surface and line metrics only.

---

## Formal Verification

Four scoring layers are formally verified by three independent methods. Verification is run
externally against the published source.

| Layer | Verified function | Method | Contracts |
|-------|-------------------|--------|-----------|
| L3 Consequence | `_assess_consequence()` — verdict enum, score bounds [0, 31], bijection, safety implications | CrossHair (PEP 316) | C1–C12 |
| L4 Structural | `analyze_structural_drift()` — dual-gate: DESTRUCTIVE requires ratio > threshold AND count ≥ min | CrossHair | S1–S7 |
| L5a Temporal | `analyze_drift()` — drift score ≥ 0, status bijection, zero-input → CURRENT | CrossHair | T1–T7 |
| L5b Semantic | `analyze_transparency()` phase 3 — MCI score ∈ [0, 1], DECEPTIVE ↔ score ≥ 0.5 | CrossHair | M1–M9 |
| L3 (abstract model) | Score bounds, monotonicity, verdict ordering | Z3 SMT | P1–P10 |
| L3 Consequence | `AssessConsequence` — full method body, all 12 postconditions | Dafny 4.x + Boogie + Z3 | POST-1–12 |
| L4 Structural | `AssessStructuralDrift` — dual-gate biconditional | Dafny | S1–S7 |
| L5a Temporal | `AnalyzeTemporalDrift` — linear drift, zero-input guarantees | Dafny | T1–T8 |

272 tests pass. All CrossHair checks exit 0. Dafny verifies the entire input domain.

Full specification: [`VERIFICATION.md`](VERIFICATION.md)
Formal spec for external auditors: [`VERIFICATION_SPEC.md`](VERIFICATION_SPEC.md)

```bash
# CrossHair — from verification/ directory
crosshair check consequence_pure --analysis_kind PEP316 --per_condition_timeout 30

# Dafny — install once, then verify
dotnet tool install --global dafny
dafny verify verification/dafny/assess_consequence.dfy

# Full Python suite
pytest tests/proofs/ -v --timeout=60
```

---

## Contributing

The test suite is the contract. Before submitting a PR:

```bash
python -m pytest test_analyzer.py -v
```

All tests must pass (currently 272). New detection signals require corresponding test coverage in the relevant test class for the layer being extended.

Open findings are tracked in `AUDIT_LOG.md`. Check there before opening a duplicate issue.

---

*PayloadGuard is maintained by [PayloadGuard-PLG](https://github.com/PayloadGuard-PLG).*
