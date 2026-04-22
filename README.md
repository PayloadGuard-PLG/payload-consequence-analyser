# PayloadGuard

Scans a branch before merge and tells you exactly how badly it's going to hurt.

> **dev:** [Dark^Vader](https://github.com/DarkVader-PLG)

---

## Contents

- [Install](#install)
- [Run](#run)
- [The forensic report](#the-forensic-report)
- [Exit codes](#exit-codes)
- [CI](#ci)
- [GitHub App](#github-app)
- [Configuration](#configuration)
- [How it works](#how-it-works)
- [The incident](#the-incident)

---

## Install

```bash
pip install -r requirements.txt
```

Python 3.8+. Core deps: GitPython, PyYAML, PyJWT, requests. Layer 4 multi-language analysis requires tree-sitter grammar packages (included in `requirements.txt` — omit any you don't need, unsupported file types are skipped silently).

---

## Run

```bash
python analyze.py <repo_path> <branch> [target]
```

```bash
# Basic scan
python analyze.py . feature-branch main

# Feed it the PR description — catches deceptive payloads
python analyze.py . feature-branch main --pr-description "minor syntax fix"

# Save a JSON report
python analyze.py . feature-branch main --save-json

# Save a markdown report
python analyze.py . feature-branch main --save-markdown reports/scan.md
```

`python analyze.py --help` if you need it.

---

## The forensic report

Every scan produces the same structured report. Here's what each section tells you and what to look for.

---

### 📅 Temporal

How old the branch is relative to the target, and which commits are being compared. A branch that's been sitting open for months while the target keeps moving is already a problem before you look at a single line.

```
📅 TEMPORAL
   Branch age: 14 days
   Branch: a1b2c3d (2026-04-08)
   Target:  e4f5g6h (2026-04-22)
```

---

### 📁 File changes

Raw scope of the changeset — files added, deleted, modified. Deletions are the number to watch. A PR that adds 2 files and deletes 40 is not a normal PR.

```
📁 FILE CHANGES
   Added:      3
   Deleted:    1
   Modified:   5
   Total:      9
```

---

### 📝 Line changes

Volume and direction of change. Deletion ratio is the derived signal — what fraction of total churn is removal. Above 50% starts raising flags; above 90% means almost everything this PR touches is being taken away.

```
📝 LINE CHANGES
   Added:        420 lines
   Deleted:       18 lines
   Net:          402 lines
   Deletion ratio: 4.1%
```

---

### 🧬 Structural drift — Layer 4

Parses every modified source file and computes exactly which named classes and functions disappeared. This is the layer that catches a file being "modified" when it's actually been gutted — line diffs alone won't tell you that `AuthManager` and `SessionStore` no longer exist.

Flags `CRITICAL` only when both conditions are met: deletion ratio exceeds the threshold **and** enough nodes were deleted. The dual gate prevents noise from small utility files.

**Supported languages:** Python · JavaScript · TypeScript · Go · Rust · Java (`.py .js .jsx .ts .tsx .go .rs .java`). Python uses stdlib AST. All others use tree-sitter — files for grammars not installed are skipped silently.

```
🧬 STRUCTURAL DRIFT (Layer 4)
   Overall severity: LOW
   Max deletion ratio: 0.0%
```

If something is actually being removed at scale:

```
🧬 STRUCTURAL DRIFT (Layer 4)
   Overall severity: CRITICAL
   src/core/auth.py: 8 nodes deleted (80.0%) [CRITICAL]
      - AuthManager
      - SessionStore
      - TokenValidator
```

---

### ⏱ Temporal drift — Layer 5a

Compound score: `branch_age_days × target_commits_per_day`. Raw age alone is a weak signal — a 90-day branch on a slow repo is nothing; on a fast repo it's a serious semantic gap. The drift score accounts for both.

| Status | Drift Score | Meaning |
|---|---|---|
| `CURRENT` | < 250 | Branch context is valid |
| `STALE` | 250 – 999 | Moderate drift — manual diff review |
| `DANGEROUS` | ≥ 1000 | Rebase required before this goes anywhere near main |

```
⏱  TEMPORAL DRIFT (Layer 5a)
   Status: CURRENT [LOW]
   Drift Score: 14.0
   Target velocity: 1.0 commits/day
   ✓ SAFE. Branch context is synchronized with target.
```

---

### 🔎 Semantic transparency — Layer 5b

Compares the PR description against the verified severity. If the description uses low-impact language ("minor fix", "typo", "cleanup") but the structural verdict is `CRITICAL`, that's a `DECEPTIVE_PAYLOAD`. Advisory signal — doesn't override the main verdict, but it shows up clearly.

| Status | Meaning |
|---|---|
| `TRANSPARENT` | Description matches what the diff actually does |
| `UNVERIFIED` | No description provided |
| `DECEPTIVE_PAYLOAD` | Description claims low impact, diff says otherwise |

```
🔎 SEMANTIC TRANSPARENCY (Layer 5b)
   Status: TRANSPARENT
   ✓ SAFE. PR description aligns with verified structural impact.
```

---

### 🔍 Verdict

The final call. Produced by the consequence model (Layer 3) which accumulates a weighted score across all signals. No single threshold triggers it — it's the combination that matters.

| Verdict | Severity | Score | Meaning |
|---|---|---|---|
| `SAFE` | LOW | 0 | Nothing notable. Proceed. |
| `REVIEW` | MEDIUM | 1–2 | Minor flags. Worth a look but not alarming. |
| `CAUTION` | HIGH | 3–4 | Real signals. Needs proper review before merge. |
| `DESTRUCTIVE` | CRITICAL | ≥ 5 | Stop. Do not merge. |

```
🔍 VERDICT: SAFE [LOW]
   ⚠️  No major red flags detected

✉️  RECOMMENDATION:
   ✓ Proceed with normal review process
```

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Fine |
| `1` | Analysis broke |
| `2` | Do not merge — wire this to block CI |

---

## CI

Drop `.github/workflows/payloadguard.yml` into your repo:

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
      - name: Checkout
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Fetch base branch
        run: git fetch origin ${{ github.base_ref }}:${{ github.base_ref }}

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install dependencies
        run: pip install -r requirements.txt

      - name: Run PayloadGuard
        id: payloadguard
        env:
          PYTHONUTF8: "1"
          PR_BODY: ${{ github.event.pull_request.body }}
          REPORT_PATH: ${{ github.workspace }}/payloadguard-report.md
        run: |
          set +e
          python analyze.py . "${{ github.head_ref }}" "${{ github.base_ref }}" \
            --pr-description "$PR_BODY" \
            --save-markdown "$REPORT_PATH"
          echo "exit_code=$?" >> "$GITHUB_OUTPUT"
          echo "report_path=$REPORT_PATH" >> "$GITHUB_OUTPUT"

      - name: Post PR comment
        if: always()
        uses: actions/github-script@v7
        env:
          REPORT_PATH: ${{ steps.payloadguard.outputs.report_path }}
        with:
          script: |
            const fs = require('fs');
            const marker = '<!-- payloadguard-report -->';
            const reportPath = process.env.REPORT_PATH;
            let body;
            try {
              body = marker + '\n' + fs.readFileSync(reportPath, 'utf8');
            } catch (e) {
              body = marker + '\n## ❌ PayloadGuard — Report not generated\n\n`' + String(e) + '`';
            }
            const { data: comments } = await github.rest.issues.listComments({
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.payload.pull_request.number,
            });
            const existing = comments.find(c => c.body.startsWith(marker));
            if (existing) {
              await github.rest.issues.updateComment({
                owner: context.repo.owner,
                repo: context.repo.repo,
                comment_id: existing.id,
                body,
              });
            } else {
              await github.rest.issues.createComment({
                owner: context.repo.owner,
                repo: context.repo.repo,
                issue_number: context.payload.pull_request.number,
                body,
              });
            }

      - name: Enforce verdict
        if: always()
        run: |
          code="${{ steps.payloadguard.outputs.exit_code }}"
          if [ "$code" = "1" ]; then
            echo "::error::PayloadGuard analysis error — check logs"
            exit 1
          elif [ "$code" = "2" ]; then
            echo "::error::PayloadGuard verdict: DESTRUCTIVE — merge blocked"
            exit 2
          fi
```

What this does:

- `fetch-depth: 0` + explicit base branch fetch — required for correct merge-base calculation; shallow clones break it
- `PR_BODY` as env var — avoids shell backtick-substitution on inline code in PR descriptions
- `PYTHONUTF8: "1"` — ensures emoji output works on all runners
- `--save-markdown` — generates the formatted report file
- `actions/github-script` posts the report as a sticky PR comment — updates on every push, never stacks duplicates
- Exit `2` fails the Enforce step. Wire a branch protection rule to require the `scan` check and the merge button is blocked

The workflow is already in this repo if you want to copy it directly from `.github/workflows/payloadguard.yml`.

---

## GitHub App

For a named **PayloadGuard** check badge in the PR checks tab (beyond the sticky comment), register a GitHub App and wire it up with three repo secrets:

| Secret | Value |
|---|---|
| `PAYLOADGUARD_APP_ID` | Your App ID |
| `PAYLOADGUARD_PRIVATE_KEY` | Contents of the generated `.pem` private key |
| `PAYLOADGUARD_INSTALLATION_ID` | Installation ID from `github.com/settings/installations` |

With those set, the workflow calls `post_check_run.py` to post a Check Run after each scan — green for SAFE, red for DESTRUCTIVE, with the full report as the body.

Without the secrets the step is a no-op; the sticky comment and merge blocking still work.

---

## Configuration

Drop a `payloadguard.yml` in your repo root. Everything is optional — omit what you don't care about and the defaults hold.

```yaml
# payloadguard.yml
thresholds:
  branch_age_days: [90, 180, 365]      # score goes up at each
  files_deleted:   [10, 20, 50]
  lines_deleted:   [5000, 10000, 50000]
  temporal:
    stale:     250                      # drift score = age × commits/day
    dangerous: 1000
  structural:
    deletion_ratio:    0.20             # fraction of AST nodes deleted
    min_deleted_nodes: 3               # both must be hit to flag CRITICAL

semantic:
  benign_keywords:
    - minor fix
    - minor syntax fix
    - typo
    - formatting
    - cleanup
    - small tweak
```

Tighten it for anything that matters:

```yaml
thresholds:
  structural:
    deletion_ratio: 0.10
    min_deleted_nodes: 2
semantic:
  benign_keywords:
    - minor fix
    - typo
    - trivial
    - nit
```

---

## How it works

Five layers. Every scan, every time.

| Layer | What it checks |
|---|---|
| 1 — Surface Scan | Files and lines changed |
| 2 — Forensic Analysis | Deletion ratio, critical path detection |
| 3 — Consequence Model | Weighted score → final verdict |
| 4 — Structural Drift | AST/tree-sitter diff — which classes and functions actually disappeared (Python, JS, TS, Go, Rust, Java) |
| 5a — Temporal Drift | Branch age × repo velocity |
| 5b — Semantic Transparency | Does the PR description match what the diff actually does |

### Scoring (Layer 3)

Points accumulate across signals. No single threshold kills you — it's the pile-up that matters.

| Signal | Thresholds | Points |
|---|---|---|
| Branch age | > 90 / 180 / 365 days | 1 / 2 / 3 |
| Files deleted | > 10 / 20 / 50 | 1 / 2 / 3 |
| Deletion ratio | > 50% / 70% / 90% | 1 / 2 / 3 |
| Structural severity | CRITICAL | 3 |
| Lines deleted | > 5k / 10k / 50k | 1 / 2 / 3 |

`≥ 5` → DESTRUCTIVE. `3–4` → CAUTION. `1–2` → REVIEW. `0` → SAFE.

---

## The incident

In April 2026, a developer received a Codex suggestion described as a *"minor syntax fix"*. The branch had been open for 10 months. Nobody looked closely enough. It would have deleted 60 files, 11,967 lines, 217 tests, and the entire application architecture in a single merge. That's what this tool was built to stop.

Below is the forensic report PayloadGuard would have produced on that branch.

```
======================================================================
PAYLOADGUARD ANALYSIS: codex-suggestion → main
======================================================================

📅 TEMPORAL
   Branch age: 312 days
   Branch: fa3c21d (2025-06-04)
   Target:  b87e90a (2026-04-22)

📁 FILE CHANGES
   Added:      2
   Deleted:   61
   Modified:   4
   Total:     67

📝 LINE CHANGES
   Added:        214 lines
   Deleted:   11,967 lines
   Net:       -11,753 lines
   Deletion ratio: 98.2%

🧬 STRUCTURAL DRIFT (Layer 4)
   Overall severity: CRITICAL
   Max deletion ratio: 94.0%
   src/core/auth.py: 12 nodes deleted (94.0%) [CRITICAL]
      - AuthManager
      - SessionStore
      - TokenValidator
      - PermissionGate
      - RoleRegistry

⏱  TEMPORAL DRIFT (Layer 5a)
   Status: DANGEROUS [CRITICAL]
   Drift Score: 3120.0
   Target velocity: 10.0 commits/day
   ❌ DO NOT MERGE. Extreme semantic drift detected. Mandatory rebase
      and manual architectural review required.

🔎 SEMANTIC TRANSPARENCY (Layer 5b)
   Status: DECEPTIVE_PAYLOAD
   Matched keyword: "minor syntax fix"
   ❌ DO NOT MERGE. PR description deliberately contradicts catastrophic
      architectural changes.

🔍 VERDICT: DESTRUCTIVE [CRITICAL]
   ⚠️  Branch is 312 days old (6+ months)
   ⚠️  61 files would be deleted (massive scope)
   ⚠️  Deletion ratio: 98.2% (almost entire changeset is deletions)
   ⚠️  Structural drift CRITICAL — significant class/function deletions detected
   ⚠️  11,967 lines would be deleted (large codebase change)

✉️  RECOMMENDATION:
   ❌ DO NOT MERGE — This would catastrophically alter the codebase

🗑️  DELETED FILES (61 total)

   CRITICAL DELETIONS:
      - tests/test_auth.py
      - tests/test_core.py
      - tests/test_integration.py
      - .github/workflows/ci.yml
      - src/core/auth.py
      - src/core/engine.py
      - requirements.txt

   OTHER DELETIONS:
      - src/modules/session.py
      - src/modules/permissions.py
      - src/modules/roles.py
      ... and 51 more files

======================================================================
```

Every signal was there. The age. The deletion ratio. The structural wipeout. The gap between what the description said and what the diff actually did. Nobody saw it. Now you will.

---

*PayloadGuard — because AI doesn't feel bad about what it breaks.*
