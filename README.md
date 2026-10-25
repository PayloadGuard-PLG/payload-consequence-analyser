# PayloadGuard

**Version:** 1.4.0 &nbsp;|&nbsp; **Status:** Production &nbsp;|&nbsp; **Updated:** October 2026

[![Dafny Verification](https://github.com/PayloadGuard-PLG/payload-consequence-analyser/actions/workflows/verify-dafny.yml/badge.svg)](https://github.com/PayloadGuard-PLG/payload-consequence-analyser/actions/workflows/verify-dafny.yml)

**Formally verified** — 36 CrossHair contracts · 10 Z3 SMT proofs · 12 Dafny postconditions · 315 tests pass · 3 independent proof methods. → [`PROOFS.md`](PROOFS.md)

PayloadGuard is a GitHub Action and multi-language consequence analysis engine that forensically scans pull requests for destructive, deceptive, or malicious code payloads before they reach your main branch.

It was built for the class of attack where a branch held open for months lands as a *"minor fix"* and wipes the codebase in a single merge — as well as subtle adversarial payloads that invert security guards, swallow transaction rollbacks, gut renamed symbols into no-op stubs, or distribute capability removals below per-file deletion thresholds. Wire it to branch protection and the merge button is blocked automatically.

---

## What PayloadGuard Detects

| Threat | Example |
|---|---|
| Mass deletion disguised as a refactor | 312-day-old branch submitted as *"minor syntax fix"*, deleting 60 files and 11,967 lines |
| Structural gutting & stub replacement | Authentication layer silently removed function by function across multiple files, or renamed and gutted into `pass` / `return None` stubs (`D02`) |
| Distributed deletion & threshold gaming | Removing 1 capability per file across 5 files (`A03`) or padding deleted security methods with trivial 1-line getters (`A06`) (`D03`) |
| Broken cross-file callers & API contracts | Deleting a function/method or tightening required parameters while callers (including aliased imports) still invoke the old contract (`D04`) |
| Security guard & rollback regression | Removing `@require_auth` decorators, dropping `self._rollback()`, inverting guard polarity (`if not verify()` $\to$ `if verify()`), inserting early `return True` bypasses, or swallowing exceptions (`D06`) |
| Deceptive PR descriptions | Description says *"update config"* — diff deletes the entire security module (`L5b`) |
| Workflow poisoning | Base64 payloads, credential exfiltration, OIDC token theft, dormant triggers (`L2c`) |
| AI tooling config poisoning | Malicious `.claude/settings.json` or `package.json` hook that executes when a developer opens the repo in an AI coding agent or IDE (`L2d`) |
| Supply chain & manifest drift | Unverified packages added to manifests (`L2b`) or manifest dependencies changed without lockfile updates (`D05`) |
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

### Standard — adds L2c, L2d, L4, L5a, L5b, and SCG Consequence Engine (`consequence.v1`)

Adds layers that catch sophisticated evasion: workflow-based attacks, AI tooling config poisoning, structural gutting distributed across files, Semantic Change Graph (SCG) differential consequence analysis, stale branches from slow-burn campaigns, and PRs with descriptions designed to mislead reviewers.

| Layer | What it adds |
|---|---|
| **L2c — Actions Poisoning** | Workflow files scanned for base64 payloads, credential exfiltration, remote-code execution, `$GITHUB_ENV` hijacking, OIDC escalation, forged identities, and `pull_request_target` checking out untrusted code |
| **L2d — AI Config Poisoning** | AI tooling config files scanned for shell commands in session hooks, folder-open tasks, lifecycle scripts, `binding.gyp` shell chains, MCP local server commands, and Cursor NL imperatives — 9 file surfaces |
| **L4 — Structural Drift** | AST-level diff — which named classes, functions, and constants were deleted, per file and cross-file |
| **SCG Consequence Engine (`consequence.v1`)** | 5-stage symbol matching across renames/moves + 6 deterministic consequence detectors (`D01`–`D06`) covering stub weakening, distributed loss (`A03`), threshold gaming (`A06`), broken callers/API contracts, manifest drift, and guard/rollback regressions (`shadow`/`advisory`/`enforce`) |
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
# Core scan (consequence engine runs in shadow mode by default)
python analyze.py . feature/auth-refactor main

# With PR description (enables semantic transparency — L5b)
python analyze.py . feature/auth-refactor main \
  --pr-description "Refactor authentication module"

# Run with SCG Consequence Engine enforcement (shadow | advisory | enforce)
python analyze.py . feature/auth-refactor main --consequence-mode enforce

# Save JSON, GitHub Markdown, and SARIF 2.1.0 Code Scanning reports
python analyze.py . feature/auth-refactor main --save-json
python analyze.py . feature/auth-refactor main --save-markdown reports/scan.md
python analyze.py . feature/auth-refactor main --save-sarif reports/payloadguard.sarif
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

consequence:
  mode: shadow                       # shadow | advisory | enforce
  max_repo_files: 200                # max head files indexed for cross-file caller verification
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
| `prt_untrusted_checkout` | CRITICAL | `pull_request_target` that checks out the PR head — privileged context executing untrusted code |
| `pull_request_target_with_write_permissions` | CRITICAL | `pull_request_target` granting any write scope |
| `workflow_remote_code_execution` | CRITICAL | Remote script fetched and piped to an interpreter. HIGH when the host is an allowlisted installer |
| `github_env_injection` | CRITICAL | `PATH`, `LD_PRELOAD` or `NODE_OPTIONS` written to `$GITHUB_ENV`, hijacking every later step |
| `oidc_elevation_typosquatted` | CRITICAL | OIDC consumer name typosquatted against a known-safe prefix |
| `prt_inherited_permissions` | HIGH | `pull_request_target` with no `permissions:` block — inherits the repository default |
| `dormant_trigger_with_payload` | HIGH | `workflow_dispatch` or `schedule` + shell execution, where no remote-execution payload was found |
| `forged_bot_author` | HIGH | Git identity configured to impersonate a known bot |
| `oidc_elevation_no_consumer` | HIGH | `id-token: write` with no recognised OIDC consumer |
| `dangerous_trigger_pull_request_target` | HIGH | `pull_request_target` with read-only permissions and no untrusted checkout |

Severity for `pull_request_target` derives from whether the workflow checks out the pull request's
head, not from which permissions it declares. Severity for a shell payload derives from the payload
itself, not from the trigger — an automatically firing trigger escalates, it never gates detection.

`workflow_remote_code_execution` allows an installer allowlist (rustup, Docker, Poetry, uv, pnpm,
Bun, Deno and similar), extensible per repository:

```yaml
actions:
  trusted_installer_hosts:
    - install.internal.example
```

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

### Structural Analysis Languages (L4 & `consequence.v1`)

| Language | Tracked constructs (`SymbolFact` v1 + legacy L4) |
|---|---|
| Python | Functions, methods, classes, async functions, module-level assignments, decorators, call sites, guard conditions, import aliases |
| JavaScript / JSX | Functions, methods, classes, arrow functions, variable declarators, ES/CommonJS exports & imports, call sites, guard conditions |
| TypeScript / TSX | Functions, methods, classes, interfaces, type aliases, enums, exports & imports, call sites, guard conditions |
| Go | Functions, receiver-qualified methods, structs, interfaces, type specs, const specs, call sites, guard conditions |
| Rust | Functions, `impl`-qualified methods, structs, enums, traits, const and static items, `use` aliases, call sites, guard conditions |
| Java | Methods, classes, interfaces, enums, annotations, visibility modifiers, call sites, guard conditions |

Files in languages without an installed grammar or with syntax errors are reported explicitly via `D01_PARSER_INCOMPLETE` (`PARSE_ERROR`, `GRAMMAR_UNAVAILABLE`, `UNSUPPORTED_EXTENSION`).

### SCG Consequence Engine (`consequence.v1`)

The Consequence Engine (`consequence_engine.py`) matches `base` and `head` symbols through a 5-stage Semantic Change Graph (SCG) pipeline (exact ID $\to$ same-container signature/body match $\to$ cross-file move $\to$ container/member similarity rename $\to$ residual `REMOVED`/`ADDED`) and runs six deterministic detectors:

| Detector ID | Consequence Classes | Epistemic Tier | Policy | What it detects |
|---|---|---|---|---|
| `D01_PARSER_INCOMPLETE` | `ANALYSIS_INCOMPLETE` | `ANALYSIS_INCOMPLETE` | `WARN` / `REVIEW` | Syntax errors (`PARSE_ERROR`), missing grammar packages, or unsupported extensions |
| `D02_BODY_WEAKENING` / `D02_AMBIGUOUS_REFACTOR` | `BODY_GUTTED`, `RENAME_WITH_BODY_WEAKENING`, `AMBIGUOUS_REFACTOR` | `VERIFIED_CONSEQUENCE` / `ANALYSIS_INCOMPLETE` | `BLOCK` / `WARN` | Surviving or renamed/moved symbols whose bodies were gutted to no-op stubs (`pass`, `...`, `return None`, empty `{}`) |
| `D03_COMPOUND_LOSS` | `DISTRIBUTED_SYMBOL_LOSS`, `THRESHOLD_GAMING_DELETION` | `VERIFIED_CONSEQUENCE` / `LIKELY_CONSEQUENCE` | `BLOCK` / `REVIEW` | Cross-file sub-threshold capability deletion (`A03`) and deletion-ratio dilution via trivial 1-line getters/comment padding (`A06`) |
| `D04_PUBLIC_API_BREAK` | `UNRESOLVED_CALLER`, `PUBLIC_API_REMOVAL`, `PUBLIC_API_SIGNATURE_BREAK`, `PUBLIC_API_VISIBILITY_REDUCED` | `VERIFIED_CONSEQUENCE` / `LIKELY_CONSEQUENCE` | `BLOCK` / `REVIEW` / `WARN` | Removed symbols with surviving cross-file callers (including aliased imports), tightened required parameters breaking call sites, or reduced export visibility |
| `D05_BUILD_DEPENDENCY_DELTA` | `BUILD_SCRIPT_MODIFICATION`, `DEPENDENCY_LOCKFILE_MISMATCH` | `VERIFIED_CONSEQUENCE` / `LIKELY_CONSEQUENCE` | `BLOCK` / `REVIEW` / `WARN` | Suspicious lifecycle script commands (`package.json`) and manifest dependency changes without accompanying lockfile updates |
| `D06_GUARD_REGRESSION` | `SECURITY_GUARD_REMOVED`, `SECURITY_GUARD_WEAKENED` | `VERIFIED_CONSEQUENCE` | `BLOCK` | Removed security decorators/rollback calls, inverted guard condition polarity (`if not verify()` $\to$ `if verify()`), neutralized guard branches (`raise` $\to$ `pass`), unconditional early-return bypasses, and swallowed exception handlers |

---

## Formal Verification

PayloadGuard's scoring and consequence models are mathematically verified to ensure deterministic outputs. A bug would have to produce a consistent false result across three independent frameworks simultaneously to go undetected.

| Framework | What is proven |
|---|---|
| **CrossHair** — symbolic execution | Consequence model (C1–C12), structural drift (S1–S7), temporal drift (T1–T7), semantic transparency (M1–M9) |
| **Z3** — SMT theorem prover | Score bounds, verdict bijection, safety-critical floors, empty-input guarantee (P1–P10) |
| **Dafny** — machine-checked proofs | Full input domain coverage, 12 postconditions verified, 0 errors (POST-1–11a + POST-12) |

**Current test state:** 315 tests pass (`test_analyzer.py` + `test_consequence_engine.py`), 7 proof-wrapper tests skipped without external solver install.

→ [`VERIFICATION.md`](VERIFICATION.md) — contracts, methods, and run instructions  
→ [`VERIFICATION_SPEC.md`](VERIFICATION_SPEC.md) — formal specification for external auditors

---

## Contributing

```bash
python -m pytest test_analyzer.py test_consequence_engine.py tests/proofs/ -q
```

315 pass, 7 skip. New detection signals require test coverage in the relevant layer's test class. Open findings are tracked in [`AUDIT_LOG.md`](AUDIT_LOG.md).

---

*PayloadGuard is maintained by [PayloadGuard-PLG](https://github.com/PayloadGuard-PLG).*
