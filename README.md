# PayloadGuard

**Version:** 1.2.0 &nbsp;|&nbsp; **Status:** Production &nbsp;|&nbsp; **Released:** May 2026

A PR analysis tool that catches destructive, deceptive, or malicious changesets before they reach main — the class of attack where a branch held open for months lands as a *"minor fix"* and wipes the codebase in a single merge.

---

## How it works

PayloadGuard runs on every PR. It scans the full diff across nine independent analysis layers and emits a single forensic verdict: **SAFE** · **REVIEW** · **CAUTION** · **DESTRUCTIVE**. Wire DESTRUCTIVE to your branch protection rules to block the merge button automatically.

---

## The nine layers

Each layer examines a different dimension of risk. They are independent — a payload that evades one is still exposed by the others.

| Layer | What it examines | Deep dive |
|---|---|---|
| **L1 — Surface** | File and line counts, deletion ratios, binary files, permission changes, symlinks | [Scoring reference](#scoring-reference) |
| **L2 — Forensic** | Critical-path deletions, security-sensitive file removal, added file content (CI triggers, shell execution) | [WHITEPAPER §3](WHITEPAPER.md) |
| **L2b — SCA** | Package manifest diffs scanned against an allowlist for unverified dependencies | [SCA config](#sca-layer-2b) |
| **L2c — Actions Poisoning** | Workflow files scanned for base64 payload delivery, credential harvesting, dormant triggers, forged bot identity, OIDC privilege escalation, unsafe `pull_request_target` | [Signal table](#github-actions-poisoning-layer-2c) |
| **L3 — Consequence Model** | Weighted scoring across all signals → single verdict | [Scoring reference](#scoring-reference) |
| **L4 — Structural Drift** | AST-level diff: which named classes, functions, and constants were actually deleted | [Supported languages](#supported-languages-layer-4) |
| **L5a — Temporal Drift** | Branch age × target repo velocity — a quantified staleness score | [Report reference](#temporal-drift-layer-5a) |
| **L5b — Semantic Transparency** | Whether the PR description matches what the diff actually does | [Signal table](#semantic-transparency-layer-5b) |
| **L5c — Runtime Agent** | eBPF tracepoints on the runner: execve, egress connect, ptrace, /proc/mem — audit or block mode | [WHITEPAPER §8](WHITEPAPER.md) |

The key layers to understand: **L4** catches structural gutting that line counts hide. **L2c** catches CI pipeline poisoning. **L5b** catches deceptive descriptions. **L3** ties it all together into a single score with proven bounds.

---

## Formal verification

The scoring logic — the part that determines verdicts — is verified by three independent methods operating on three different representations of the same code.

| Method | What it operates on | What it proves |
|---|---|---|
| **Z3 SMT** | Abstract scoring model | Monotonicity, verdict ordering, score bounds — P1–P10 |
| **CrossHair** | Actual Python source | 35 contracts across 4 layers — C1–C12, S1–S7, T1–T7, M1–M9 |
| **Dafny + Z3** | Dafny reference implementation | Machine-checked postconditions over the entire input domain — 9 verified, 0 errors |

A scoring bug would have to produce a consistent false result across all three representations simultaneously to go undetected.

**273 tests pass.** All CrossHair checks exit 0. No counterexamples found.

→ [`VERIFICATION.md`](VERIFICATION.md) — full specification, contracts, and run instructions  
→ [`VERIFICATION_SPEC.md`](VERIFICATION_SPEC.md) — formal spec for external auditors

---

## Quick start

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

Set the `scan` job as a required status check in your branch protection rules. DESTRUCTIVE PRs fail the check and cannot be merged.

**Exit codes:** `0` = SAFE / REVIEW / CAUTION · `1` = analysis error · `2` = DESTRUCTIVE

---

## What a report looks like

This is the forensic report PayloadGuard would have produced on the April 2026 incident — a branch open for 312 days, submitted as a *"minor syntax fix"*, containing a diff that would have deleted 60 files, 11,967 lines, and the entire application architecture.

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
   ❌ DO NOT MERGE. PR description is inconsistent with actual diff scope.

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

Every signal was present and quantifiable before the merge button was pressed.

---

## Installation

### Python package

```bash
pip install payloadguard-plg
```

### From source

```bash
git clone https://github.com/PayloadGuard-PLG/payload-consequence-analyser.git
pip install -r requirements.txt
```

**Requirements:** Python 3.8+. Core: GitPython, PyYAML, PyJWT, requests. Layer 4 multi-language structural analysis requires tree-sitter grammar packages (included in `requirements.txt`).

---

## CLI usage

```bash
python analyze.py <repo_path> <branch> [target_branch]

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

## Layer reference

### GitHub Actions poisoning (Layer 2c)

Scans every added or modified `.github/workflows/` file. Hardened against multiline YAML block scalar splitting, OIDC consumer typosquatting, and two-tier `pull_request_target` scoring.

| Signal | Severity | Description |
|---|---|---|
| `base64_payload` | CRITICAL | Base64-encoded content piped to a shell interpreter |
| `credential_harvest` | CRITICAL | Env var exfiltration, cloud metadata endpoint, secret grep — including multiline curl constructs |
| `pull_request_target_with_write_permissions` | CRITICAL | `pull_request_target` + write permissions — pwn-request attack vector |
| `dormant_trigger_with_payload` | HIGH | `workflow_dispatch` or `schedule` trigger + shell execution — hidden activation path |
| `forged_bot_author` | HIGH | Git identity configured to impersonate a known bot |
| `oidc_elevation_no_consumer` | HIGH | `id-token: write` with no recognised OIDC consumer present |
| `dangerous_trigger_pull_request_target` | HIGH | `pull_request_target` without write permissions |

### Temporal drift (Layer 5a)

`drift_score = branch_age_days × target_commits_per_day`

| Status | Score | Meaning |
|---|---|---|
| CURRENT | < 250 | Branch context is valid |
| STALE | 250–999 | Significant divergence — review diff carefully |
| DANGEROUS | ≥ 1,000 | Rebase required |

### Semantic transparency (Layer 5b)

Three-phase heuristic: Linguistic Lexer → Diff Profiler → Cross-Correlation. Derives `mci_score ∈ [0,1]` from five independent signals.

| Signal | MCI weight | Trigger |
|---|---|---|
| `scope_understated` | +0.4 | Micro-scope language with churn > 50 lines |
| `phantom_additions` | +0.4 | Remedial claim ("fix", "patch") with insertion ratio > 90% |
| `operation_mutation` | +0.3 | Micro-scope language with structural additions in diff |
| `hidden_component_modification` | +0.3 | Sensitive file in diff not named in description |
| `cross_stack_micro_claim` | +0.2 | Micro-scope language touching ≥ 3 distinct file types |

`mci_score ≥ 0.5` → DECEPTIVE_PAYLOAD (escalates verdict). `> 0` → CAUTION_MISMATCH.

---

## Scoring reference

### Score contributions

| Signal | Points |
|---|---|
| Branch age > 90 / 180 / 365 days | +1 / +2 / +3 |
| Files deleted > 10 / 20 / 50 | +1 / +2 / +3 |
| Deletion ratio > 50% / 70% / 90% (≥100 lines only) | +1 / +2 / +3 |
| Lines deleted > 5k / 10k / 50k | +1 / +2 / +3 |
| Critical path files deleted | +2 |
| Security files deleted | +5 |
| Structural severity CRITICAL | +3 |
| Unverified dependency (SCA, per package) | +3 |
| Added file content: shell or CI patterns | +2 per match |
| Actions poisoning CRITICAL signal | +5 |
| Actions poisoning HIGH signal | +3 |

The three deletion dimensions (files, ratio, lines) are correlated and capped: `min(4, max(files, ratio, lines) + 1 if ≥2 non-zero)`.

### Verdict thresholds

| Score | Verdict | Exit code |
|---|---|---|
| 0 | SAFE | 0 |
| 1–2 | REVIEW | 0 |
| 3–4 | CAUTION | 0 |
| ≥ 5 | DESTRUCTIVE | 2 |

---

## Configuration

Place `payloadguard.yml` in your repository root. All fields optional.

```yaml
thresholds:
  branch_age_days: [90, 180, 365]
  files_deleted:   [10, 20, 50]
  lines_deleted:   [5000, 10000, 50000]
  temporal:
    stale:     250
    dangerous: 1000
  structural:
    deletion_ratio:    0.20
    min_deleted_nodes: 3

sca:
  fail_on_unknown: true

actions:
  enabled: true
  critical_signal_score: 5
  high_signal_score: 3
  trusted_oidc_consumers:
    - my-org/custom-deploy-action

semantic:
  micro_scope_churn_limit: 50
  insertion_ratio_fix_threshold: 0.9
```

### SCA (Layer 2b)

Create `allowlist.yml` listing approved packages. Any package in a manifest diff not on the allowlist scores +3.

```yaml
packages:
  - requests
  - numpy
  - django
```

---

## GitHub App

To post a named check run in the PR checks tab, register a GitHub App and configure three secrets:

| Secret | Value |
|---|---|
| `PAYLOADGUARD_APP_ID` | App ID from GitHub App settings |
| `PAYLOADGUARD_PRIVATE_KEY` | RSA private key (PEM format) |
| `PAYLOADGUARD_INSTALLATION_ID` | Installation ID from `github.com/settings/installations` |

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

Without the App secrets the step is a no-op. PR comment and merge enforcement still function.

---

## Supported languages (Layer 4)

| Language | Tracked constructs |
|---|---|
| Python | Functions, classes, async functions, module-level assignments, annotated assignments |
| JavaScript / JSX | Functions, classes, arrow functions, variable declarators |
| TypeScript / TSX | Functions, classes, interfaces, type aliases, enums |
| Go | Functions, methods, type specs, const specs |
| Rust | Functions, structs, enums, traits, const and static items |
| Java | Methods, classes, interfaces, enums |

Files in languages without an installed grammar are skipped silently.

---

## Contributing

```bash
python -m pytest test_analyzer.py -v
```

All tests must pass (currently 273). New detection signals require test coverage in the relevant layer's test class. Open findings are tracked in [`AUDIT_LOG.md`](AUDIT_LOG.md).

---

*PayloadGuard is maintained by [PayloadGuard-PLG](https://github.com/PayloadGuard-PLG).*
