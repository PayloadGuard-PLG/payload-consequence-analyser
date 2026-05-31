# PayloadGuard

**Version:** 1.3.0 &nbsp;|&nbsp; **Status:** Production &nbsp;|&nbsp; **Released:** May 2026

PayloadGuard is a static analysis GitHub Action that forensically intercepts and evaluates pull requests for destructive, deceptive, or malicious code payloads. It performs a 9-layer architectural diff scan and emits a deterministic verdict to automatically block catastrophic merges before they reach the main branch — the class of attack where a branch held open for months lands as a *“minor fix”* and wipes the codebase in a single merge.

---

## Formal Verification: Mathematical Proofs of Correctness

PayloadGuard’s scoring and consequence models are mathematically verified to ensure deterministic outputs. A bug would have to produce a consistent false result across three independent verification frameworks simultaneously to go undetected.

The analysis engines are validated via:

- **CrossHair** — Symbolic execution directly on the active Python source code. Evaluates the consequence model (C1–C12), structural drift (S1–S7), temporal drift (T1–T7), and semantic transparency (M1–M9).
- **Z3 Theorem Prover** — Satisfiability Modulo Theories (SMT) proofs executed on an abstract scoring model. Covers score bounds, verdict bijection, safety-critical floors, and empty-input guarantee (P1–P10).
- **Dafny** — Machine-checked proofs over the entire input domain. 11 postconditions verified, 0 errors (POST-1–11a).

**Current test state:** 273 tests pass, 7 skipped.

→ [`VERIFICATION.md`](VERIFICATION.md) — contracts, methods, and run instructions  
→ [`VERIFICATION_SPEC.md`](VERIFICATION_SPEC.md) — formal specification for external auditors  
→ [`llms.txt`](llms.txt) — machine-readable schema for AI ingestion

---

## How PayloadGuard Analyzes Pull Requests

PayloadGuard runs automatically on every pull request. It scans the full diff across nine independent analysis layers and calculates a definitive consequence score, emitting one of four verdicts: **SAFE** · **REVIEW** · **CAUTION** · **DESTRUCTIVE**.

Wire **DESTRUCTIVE** to your branch protection rules and the merge button is blocked automatically.

---

## Quick Start: GitHub Actions Integration

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

**Deterministic pipeline outputs** — the exit code is a guaranteed state change produced by the scoring pipeline:

| Exit code | Verdict | Condition |
|---|---|---|
| `0` | SAFE / REVIEW / CAUTION | `severity_score` in range [0, 4] |
| `1` | Analysis error | Pipeline failure — treat as inconclusive |
| `2` | DESTRUCTIVE | `severity_score` ≥ 5 — merge blocked |

---

## The Nine Forensic Analysis Layers

Each layer examines an isolated dimension of risk. A payload designed to evade one layer will be exposed by the cross-correlation of the others.

| Layer | What it examines | Verified |
|---|---|---|
| **L1 — Surface** | File and line counts, deletion ratios, binary files, permission changes, symlinks | — |
| **L2 — Forensic** | Critical-path deletions, security-sensitive file removal, added file content (CI triggers, shell execution) | — |
| **L2b — SCA** | Package manifest diffs scanned against an allowlist for unverified dependencies | — |
| **L2c — Actions Poisoning** | Workflow files: base64 payload, credential harvesting, dormant triggers, forged bot identity, OIDC escalation, unsafe `pull_request_target` | — |
| **L3 — Consequence Model** | Weighted scoring across all signals → single verdict | ✅ CrossHair C1–C12 · Z3 P1–P10 · Dafny POST-1–11a |
| **L4 — Structural Drift** | AST-level diff: which named classes, functions, and constants were deleted | ✅ CrossHair S1–S7 · Dafny S1–S7 |
| **L4b — Complexity** | McCabe V(G) advisory for newly added Python functions (informational, no score impact) | — |
| **L5a — Temporal Drift** | Branch age × target repo velocity — a quantified staleness score | ✅ CrossHair T1–T7 · Dafny T1–T8 |
| **L5b — Semantic Transparency** | Whether the PR description matches what the diff actually does | ✅ CrossHair M1–M9 |
| **L5c — Runtime Agent** | eBPF tracepoints on the runner: execve, egress connect, ptrace, /proc/mem — audit or block mode | — |

---

## Forensic Report: April 2026 Incident Reconstruction

This is the report PayloadGuard would have produced on the April 2026 incident — a branch open for 312 days, submitted as a *“minor syntax fix”*, containing a diff that would have deleted 60 files, 11,967 lines, and the entire application architecture.

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

## CLI Usage

```bash
# Scan a branch against main
python analyze.py . feature/auth-refactor main

# Include the PR description for semantic analysis (recommended)
python analyze.py . feature/auth-refactor main \
  --pr-description "Refactor authentication module"

# Output reports
python analyze.py . feature/auth-refactor main --save-json
python analyze.py . feature/auth-refactor main --save-markdown reports/scan.md
```

---

## Technical Reference: Scoring Logic and Signal Definitions

### Verdict Bijection: L3 Consequence Model

The verdict is a deterministic bijection of `severity_score`. Proven by CrossHair (C4–C7), Z3 (P4–P7), and Dafny (POST-4–7).

$$\text{verdict}(s) = \begin{cases} \text{SAFE} & s = 0 \\ \text{REVIEW} & 1 \leq s \leq 2 \\ \text{CAUTION} & 3 \leq s \leq 4 \\ \text{DESTRUCTIVE} & s \geq 5 \end{cases}$$

where $s = \text{severity\_score} \in [0,\ 31]$.

### Score Contributions

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
| Added file content: shell or CI patterns | +2 per match, capped +4 |
| Actions poisoning CRITICAL signal | +5 |
| Actions poisoning HIGH signal | +3 |

**Deletion dimension cap** — the three deletion sub-scores (files $S_f$, ratio $S_r$, lines $S_l$) are correlated and capped to prevent triple-counting:

$$S_{\text{deletion}} = \min\!\left(4,\ \max(S_f, S_r, S_l) + \mathbf{1}\!\left[\lvert\{i : S_i > 0\}\rvert \geq 2\right]\right)$$

### GitHub Actions Poisoning Signals: Layer 2c

Scans every added or modified `.github/workflows/` file. Hardened against multiline YAML block scalar splitting, OIDC consumer typosquatting, and two-tier `pull_request_target` scoring.

| Signal | Severity | Description |
|---|---|---|
| `base64_payload` | CRITICAL | Base64-encoded content piped to a shell interpreter |
| `credential_harvest` | CRITICAL | Env var exfiltration, cloud metadata endpoint, secret grep — including multiline curl constructs |
| `pull_request_target_with_write_permissions` | CRITICAL | `pull_request_target` + write permissions — pwn-request attack vector |
| `oidc_elevation_typosquatted` | CRITICAL | `id-token: write` + consumer action name resembles a known-safe prefix but is not (`aws-actions-unofficial/`, `google-github-actions-fork/`, etc.) |
| `dormant_trigger_with_payload` | HIGH | `workflow_dispatch` or `schedule` trigger + shell execution — hidden activation path |
| `forged_bot_author` | HIGH | Git identity configured to impersonate a known bot |
| `oidc_elevation_no_consumer` | HIGH | `id-token: write` with no recognised OIDC consumer present |
| `dangerous_trigger_pull_request_target` | HIGH | `pull_request_target` without write permissions |

### Temporal Drift: Layer 5a

Temporal drift quantifies branch staleness as the product of branch age and target repository commit velocity. Verified by CrossHair (T1–T7) and Dafny (T1–T8).

$$\text{drift\_score} = D_{\text{branch}} \times V_{\text{target}}$$

where:

- $D_{\text{branch}}$ = branch age in calendar days (clamped to 0 if branch is newer than target)
- $V_{\text{target}}$ = target repository commit velocity in commits per day

| Status | drift_score | Meaning |
|---|---|---|
| CURRENT | < 250 | Branch context is valid |
| STALE | 250–999 | Significant divergence — review diff carefully |
| DANGEROUS | ≥ 1,000 | Rebase required |

### Semantic Transparency: Layer 5b

The PR-MCI heuristic derives a continuous score measuring the consistency between a PR description and the actual diff. Verified by CrossHair (M1–M9).

Three-phase pipeline: **Linguistic Lexer** → **Diff Profiler** → **Cross-Correlation**.

$$\text{mci\_score} = \min\!\left(1,\ \sum_{i=1}^{5} w_i \cdot \mathbf{1}[\text{signal}_i]\right), \quad \text{mci\_score} \in [0,\ 1]$$

where:

| Signal $i$ | Weight $w_i$ | Trigger condition |
|---|---|---|
| `scope_understated` | 0.4 | Micro-scope language with churn > 50 lines |
| `phantom_additions` | 0.4 | Remedial claim (“fix”, “patch”) with insertion ratio > 90% |
| `operation_mutation` | 0.3 | Micro-scope language with structural additions in diff |
| `hidden_component_modification` | 0.3 | Sensitive file in diff not named in description |
| `cross_stack_micro_claim` | 0.2 | Micro-scope language touching ≥ 3 distinct file types |

Verdict escalation: `mci_score ≥ 0.5` → DECEPTIVE_PAYLOAD (escalates verdict one tier). `mci_score > 0` → CAUTION_MISMATCH.

### Supported Languages: Layer 4

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

## Contributing

```bash
python -m pytest test_analyzer.py tests/proofs/ -q
```

273 pass, 7 skip. New detection signals require test coverage in the relevant layer’s test class. Open findings are tracked in [`AUDIT_LOG.md`](AUDIT_LOG.md).

---

*PayloadGuard is maintained by [PayloadGuard-PLG](https://github.com/PayloadGuard-PLG).*
