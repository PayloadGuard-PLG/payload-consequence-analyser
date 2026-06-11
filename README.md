# PayloadGuard

**Version:** 1.4.0-dev &nbsp;|&nbsp; **Status:** Production &nbsp;|&nbsp; **Released:** May 2026

[![Dafny Verification](https://github.com/PayloadGuard-PLG/payload-consequence-analyser/actions/workflows/verify-dafny.yml/badge.svg)](https://github.com/PayloadGuard-PLG/payload-consequence-analyser/actions/workflows/verify-dafny.yml)

**Formally verified** — 36 CrossHair contracts · 10 Z3 SMT proofs · 12 Dafny postconditions · 274 tests pass · 3 independent proof methods. → [`PROOFS.md`](PROOFS.md)

PayloadGuard is a GitHub Action that forensically scans pull requests for destructive, deceptive, or malicious code payloads before they reach your main branch.

It was built for the class of attack where a branch held open for months lands as a *"minor fix"* and wipes the codebase in a single merge. Wire it to branch protection and the merge button is blocked automatically — no human review required.

---

## What PayloadGuard Detects

| Threat | Example |
|---|---|
| Mass deletion disguised as a refactor | 312-day-old branch submitted as *"minor syntax fix"*, deleting 60 files and 11,967 lines |
| Structural gutting | Authentication layer silently removed function by function across multiple files |
| Deceptive PR descriptions | Description says *"update config"* — diff deletes the entire security module |
| Workflow poisoning | Base64 payloads, credential exfiltration, OIDC token theft, dormant triggers |
| AI tooling config poisoning | Malicious `.claude/settings.json` or `package.json` hook that executes when a developer opens the repo in an AI coding agent or IDE |
| Supply chain injection | Unverified packages added to manifests under the radar |
| Typosquatted CI actions | `aws-actions-unofficial/` instead of `aws-actions/` — OIDC token handed to attacker |

---

## Analysis Tiers

PayloadGuard has three tiers of analysis. Each tier is a superset of the one before it. Start with **Core** and add tiers as your threat model requires.

```
┌─────────────────────────────────────────────────────────────┐
│  CORE  (L1 · L2 · L3)                                       │
│  Surface scan → Forensic analysis → Verdict                 │
│  Dependency: GitPython only                                 │
├─────────────────────────────────────────────────────────────┤
│  STANDARD  (adds L2c · L2d · L4 · L5a · L5b)               │
│  + Workflow poisoning · AI config poisoning                 │
│  + Structural drift · Temporal drift · Semantic transparency│
│  Dependency: adds tree-sitter grammars                      │
├─────────────────────────────────────────────────────────────┤
│  FULL  (adds L5c)                                           │
│  + eBPF runtime agent — blocks exfiltration on the runner   │
│  Dependency: adds Linux BPF support                         │
└─────────────────────────────────────────────────────────────┘
```

### Core — L1, L2, L3

The minimum viable deployment. Catches bulk deletion attacks, critical-path file removal, suspicious added files, and unverified dependency injection. No additional system dependencies beyond GitPython.

| Layer | What it does |
|---|---|
| **L1 — Surface Scan** | File and line counts, deletion ratios, binary files, permission changes, symlinks |
| **L2 — Forensic Analysis** | Critical-path deletions, security-sensitive file removal, added file content (shell patterns, CI triggers) |
| **L2b — SCA** | Package manifest diffs scanned against your allowlist for unverified dependencies |
| **L3 — Consequence Model** | Weighted scoring across all signals → single deterministic verdict |

**Verdict:** SAFE · REVIEW · CAUTION · DESTRUCTIVE  
**Exit codes:** `0` = SAFE/REVIEW/CAUTION · `1` = analysis error · `2` = DESTRUCTIVE (merge blocked)

### Standard — adds L2c, L4, L5a, L5b

Adds four layers that catch sophisticated evasion: workflow-based attacks, structural gutting distributed across files, stale branches from slow-burn campaigns, and PRs with descriptions designed to mislead reviewers.

| Layer | What it adds |
|---|---|
| **L2c — Actions Poisoning** | Workflow files scanned for base64 payloads, credential exfiltration, OIDC escalation, forged identities, dormant triggers, unsafe `pull_request_target` |
| **L2d — AI Config Poisoning** | AI tooling config files scanned for shell commands in session hooks, folder-open tasks, lifecycle scripts, `binding.gyp` shell chains, MCP local server commands, and Cursor NL imperatives — 9 file surfaces |
| **L4 — Structural Drift** | AST-level diff — which named classes, functions, and constants were deleted, per file and cross-file |
| **L5a — Temporal Drift** | Branch age × target commit velocity — quantified staleness score to catch slow-burn campaigns |
| **L5b — Semantic Transparency** | Whether the PR description matches what the diff actually does |

**Additional dependency:** tree-sitter grammar packages (Python, JS/TS, Go, Rust, Java — see `requirements.txt`)

### Full — adds L5c

Adds the eBPF runtime agent to monitor the CI runner itself during a scan. Captures outbound network connections, process execution, ptrace activity, and `/proc/mem` access. Can operate in audit or block mode.

| Layer | What it adds |
|---|---|
| **L5c — Runtime Agent** | eBPF tracepoints: execve · egress connect · ptrace · procmem — audit log or block mode |

**Additional dependency:** Linux kernel with BPF support. Requires elevated runner permissions (`SYS_BPF`, `SYS_PTRACE`). See [Runtime Agent setup](#runtime-agent-l5c).

---

## Quick Start

### Core (recommended starting point)

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

Set the `scan` job as a **required status check** in your branch protection rules. DESTRUCTIVE PRs fail the check and cannot be merged.

### Standard (adds workflow + structural analysis)

Same workflow as above — all Standard layers activate automatically when tree-sitter grammars are available. The action installs them via `requirements.txt` on the runner.

To add the PR description for semantic analysis (recommended):

```yaml
        with:
          repo-token: ${{ secrets.GITHUB_TOKEN }}
          pr-description: ${{ github.event.pull_request.body }}
```

### Full (adds eBPF runtime agent)

```yaml
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
        env:
          PAYLOADGUARD_RUNTIME: "1"
```

The runtime agent requires a Linux runner with BPF capabilities. See [Runtime Agent setup](#runtime-agent-l5c) for kernel requirements and block-mode configuration.

---

## Installation

### From the GitHub Actions Marketplace

Reference `PayloadGuard-PLG/payload-consequence-analyser@main` in your workflow. No local install required.

### Python package

```bash
pip install payloadguard-plg
```

### From source

```bash
git clone https://github.com/PayloadGuard-PLG/payload-consequence-analyser.git

# Core only (GitPython, PyYAML, PyJWT, requests)
pip install gitpython pyyaml pyjwt requests

# Standard (adds tree-sitter grammars for L4 structural analysis)
pip install -r requirements.txt
```

**Python 3.8+** required.

---

## CLI Usage

Scan a branch locally without opening a PR:

```bash
# Core scan
python analyze.py . feature/auth-refactor main

# With PR description (enables semantic transparency — L5b)
python analyze.py . feature/auth-refactor main \
  --pr-description "Refactor authentication module"

# Save reports
python analyze.py . feature/auth-refactor main --save-json
python analyze.py . feature/auth-refactor main --save-markdown reports/scan.md
```

---

## Real Incident Reconstruction

This is the verdict PayloadGuard would have produced on the April 2026 incident — a branch open for 312 days, submitted as a *"minor syntax fix"*, containing a diff that deleted 60 files, 11,967 lines, and the entire application architecture.

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

## GitHub App (optional — named check runs)

Without GitHub App secrets the scan still runs and the verdict is enforced via exit code. The App is only needed to post a named **PayloadGuard** check in the PR checks tab.

Register a GitHub App and add three secrets to your repo:

| Secret | Value |
|---|---|
| `PAYLOADGUARD_APP_ID` | App ID from GitHub App settings |
| `PAYLOADGUARD_PRIVATE_KEY` | RSA private key (PEM format) |
| `PAYLOADGUARD_INSTALLATION_ID` | Installation ID from `github.com/settings/installations` |

```yaml
        with:
          repo-token: ${{ secrets.GITHUB_TOKEN }}
          pr-description: ${{ github.event.pull_request.body }}
          app-id: ${{ secrets.PAYLOADGUARD_APP_ID }}
          private-key: ${{ secrets.PAYLOADGUARD_PRIVATE_KEY }}
          installation-id: ${{ secrets.PAYLOADGUARD_INSTALLATION_ID }}
```

---

## Configuration

Place `payloadguard.yml` in your repository root to override defaults. All fields are optional.

```yaml
thresholds:
  branch_age_days: [90, 180, 365]    # days → +1/+2/+3 score
  files_deleted:   [10, 20, 50]      # files → +1/+2/+3 score
  lines_deleted:   [5000, 10000, 50000]
  temporal:
    stale:     250                   # drift_score threshold (STALE)
    dangerous: 1000                  # drift_score threshold (DANGEROUS)
  structural:
    deletion_ratio:    0.20          # 20% of nodes deleted → CRITICAL
    min_deleted_nodes: 3

sca:
  fail_on_unknown: true              # unverified package → +3 score

actions:
  enabled: true
  critical_signal_score: 5
  high_signal_score: 3
  trusted_oidc_consumers:
    - my-org/custom-deploy-action    # add your own OIDC consumers here

semantic:
  micro_scope_churn_limit: 50
  insertion_ratio_fix_threshold: 0.9
```

### SCA Allowlist (Layer 2b)

Create `allowlist.yml` listing approved packages. Any package in a manifest diff not on the allowlist scores +3.

```yaml
packages:
  - requests
  - numpy
  - django
```

---

## Runtime Agent: L5c

The eBPF agent monitors the CI runner itself during execution. It captures four event types:

| Event | What it catches |
|---|---|
| `execve` | Unexpected process spawning — shells, interpreters, downloaders |
| `egress_connect` | Outbound network connections — data exfiltration, C2 callbacks |
| `ptrace_attach` | Process injection attempts |
| `procmem_open` | `/proc/<pid>/mem` read access — memory scraping |

**Kernel requirements:** Linux 5.4+ with `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`. The agent uses BTF type info — kernel must be compiled with `CONFIG_DEBUG_INFO_BTF=y`.

**Audit mode** (default) — events are logged to the JSON report. No blocking.

**Block mode** — set `PAYLOADGUARD_RUNTIME_BLOCK=1`. Detected events send `SIGKILL` to the offending process.

```yaml
        env:
          PAYLOADGUARD_RUNTIME: "1"
          PAYLOADGUARD_RUNTIME_BLOCK: "1"    # optional — block rather than audit
```

---

## Technical Reference

### Verdict Scoring

The verdict is a deterministic function of `severity_score ∈ [0, 36]`:

| Score | Verdict | Meaning |
|---|---|---|
| 0 | SAFE | No signals detected |
| 1–2 | REVIEW | Minor signals — human review recommended |
| 3–4 | CAUTION | Elevated signals — scrutinise before merging |
| ≥ 5 | DESTRUCTIVE | Merge blocked |

### Score Contributions

| Signal | Points |
|---|---|
| Branch age > 90 / 180 / 365 days | +1 / +2 / +3 |
| Files deleted > 10 / 20 / 50 | +1 / +2 / +3 |
| Deletion ratio > 50% / 70% / 90% (≥100 lines) | +1 / +2 / +3 |
| Lines deleted > 5k / 10k / 50k | +1 / +2 / +3 |
| Critical path files deleted | +2 |
| Security files deleted | +5 |
| Structural severity CRITICAL (L4) | +5 |
| Unverified dependency — SCA (per package) | +3 |
| Added file content: shell or CI patterns | +2 per match, capped +4 |
| Actions poisoning CRITICAL signal (L2c) | +5 |
| Actions poisoning HIGH signal (L2c) | +3 |
| AI config poisoning CRITICAL signal (L2d) | +5 |
| AI config poisoning HIGH signal (L2d) | +3 |

The three deletion sub-scores (files, ratio, lines) are correlated and capped to prevent triple-counting.

### Actions Poisoning Signals (L2c)

| Signal | Severity | Description |
|---|---|---|
| `base64_payload` | CRITICAL | Base64-encoded content piped to a shell interpreter |
| `credential_harvest` | CRITICAL | Env var exfiltration, cloud metadata endpoint, secret grep |
| `pull_request_target_with_write_permissions` | CRITICAL | pwn-request attack vector |
| `oidc_elevation_typosquatted` | CRITICAL | OIDC consumer name typosquatted against a known-safe prefix |
| `dormant_trigger_with_payload` | HIGH | `workflow_dispatch` or `schedule` + shell execution — hidden activation |
| `forged_bot_author` | HIGH | Git identity configured to impersonate a known bot |
| `oidc_elevation_no_consumer` | HIGH | `id-token: write` with no recognised OIDC consumer |
| `dangerous_trigger_pull_request_target` | HIGH | `pull_request_target` without write permissions |

### AI Config Poisoning Signals (L2d)

Scans added or modified AI tooling config files across 9 surfaces: `.claude/settings.json`, `.gemini/settings.json`, `.cursor/rules/*.mdc`, `.vscode/tasks.json`, `package.json`, `composer.json`, `Gemfile`, `binding.gyp`, and `mcp.json`.

| Signal | Severity | Description |
|---|---|---|
| `command_in_session_hook` | CRITICAL | Shell command in a Claude/Gemini `SessionStart` hook |
| `command_in_folder_open_task` | CRITICAL | VS Code task with `runOn: folderOpen` + dangerous shell command |
| `lifecycle_script_hijack` | CRITICAL | `preinstall`/`postinstall`/`prepare` npm script with dangerous command |
| `composer_post_install` | CRITICAL | Composer `post-install-cmd` / `post-update-cmd` with dangerous command |
| `gemfile_system_call` | CRITICAL | Top-level `system()`, `exec()`, or backtick expression in a Gemfile |
| `binding_gyp_command_substitution` | CRITICAL | Shell chain (`\|\|`, `&&`, output redirect) inside a `binding.gyp` `<!()` |
| `cursor_nl_exec_imperative` | HIGH | Cursor rule with `alwaysApply: true` and an execute imperative |
| `mcp_local_server_command` | HIGH | MCP server config launching a repo-local script |
| `hidden_unicode` | HIGH | Zero-width, bidi, or Unicode tag-block characters in any config value |

### Temporal Drift (L5a)

`drift_score = branch_age_days × target_commits_per_day`

| Status | drift_score | Meaning |
|---|---|---|
| CURRENT | < 250 | Branch context is valid |
| STALE | 250–999 | Significant divergence — review diff carefully |
| DANGEROUS | ≥ 1,000 | Rebase required before merging |

### Structural Analysis Languages (L4)

| Language | Tracked constructs |
|---|---|
| Python | Functions, classes, async functions, module-level assignments |
| JavaScript / JSX | Functions, classes, arrow functions, variable declarators |
| TypeScript / TSX | Functions, classes, interfaces, type aliases, enums |
| Go | Functions, methods, type specs, const specs |
| Rust | Functions, structs, enums, traits, const and static items |
| Java | Methods, classes, interfaces, enums |

Files in languages without an installed grammar are skipped silently.

---

## Formal Verification

PayloadGuard's scoring and consequence models are mathematically verified to ensure deterministic outputs. A bug would have to produce a consistent false result across three independent frameworks simultaneously to go undetected.

| Framework | What is proven |
|---|---|
| **CrossHair** — symbolic execution | Consequence model (C1–C12), structural drift (S1–S7), temporal drift (T1–T7), semantic transparency (M1–M9) |
| **Z3** — SMT theorem prover | Score bounds, verdict bijection, safety-critical floors, empty-input guarantee (P1–P10) |
| **Dafny** — machine-checked proofs | Full input domain coverage, 12 postconditions verified, 0 errors (POST-1–11a + POST-12) |

**Current test state:** 274 tests pass, 7 skipped.

→ [`VERIFICATION.md`](VERIFICATION.md) — contracts, methods, and run instructions  
→ [`VERIFICATION_SPEC.md`](VERIFICATION_SPEC.md) — formal specification for external auditors

---

## Contributing

```bash
python -m pytest test_analyzer.py tests/proofs/ -q
```

274 pass, 7 skip. New detection signals require test coverage in the relevant layer's test class. Open findings are tracked in [`AUDIT_LOG.md`](AUDIT_LOG.md).

---

*PayloadGuard is maintained by [PayloadGuard-PLG](https://github.com/PayloadGuard-PLG).*
