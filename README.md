# PayloadGuard

**Status:** v1.1.0 production release — May 2026  
**Live on:** `PayloadGuard-PLG/payload-consequence-analyser@main` (`d843549`)

**PayloadGuard** is a 5-layer branch analysis tool that scans a pull request before it merges and produces a forensic verdict on the risk of the changeset. It was built to stop the class of attack where a destructive diff is hidden behind a harmless-sounding description — and to catch it before a human reviewer has to.

Each scan produces a verdict: **SAFE**, **REVIEW**, **CAUTION**, or **DESTRUCTIVE**. In CI it posts a GitHub Check Run with a full contextual report. Wire the exit code to a branch protection rule and DESTRUCTIVE verdicts block the merge button automatically.

| Layer | What it checks |
|---|---|
| 1 — Surface Scan | Files and lines changed, deletion ratios, binary file handling |
| 2 — Forensic Analysis | Critical-path file detection, deletion ratios, file permission changes, symlink/submodule detection, added file content scanning |
| 2b — SCA Analysis | Package manifest diff scanning, hallucination defense via allowlist (opt-in) |
| 3 — Consequence Model | Weighted scoring across all signals → final verdict |
| 4 — Structural Drift | AST diff — which named classes, functions, and constants actually disappeared |
| 4b — Complexity Advisory | McCabe V(G) for newly added functions (informational) |
| 5a — Temporal Drift | Branch age × repo velocity — how stale is the context |
| 5b — Semantic Transparency | Does the PR description match what the diff actually does |

> **dev:** [Dark^Vader](https://github.com/DarkVader-PLG)

---
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
pip install payloadguard-plg
```

Or from source:

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

Branch age and the commits being compared. A long-lived branch may have diverged significantly from what the target codebase now looks like.

```
📅 TEMPORAL
   Branch age: 14 days
   Branch: a1b2c3d (2026-04-08)
   Target:  e4f5g6h (2026-04-22)

Branch is 14 days old — context is fresh.
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

1 file(s) deleted — within normal range (flag threshold: >10).
```

---

### 📝 Line changes

Volume and direction of change. Deletion ratio measures what fraction of total churn is removal. Above 50% starts raising flags; above 90% means almost everything this PR touches is being taken away.

> **Note:** The deletion ratio gate only fires when at least 100 lines are deleted. A 5-deleted/15-added PR won't be flagged on ratio alone — absolute scale matters.

```
📝 LINE CHANGES
   Added:        420 lines
   Deleted:       18 lines
   Net:          +402 lines
   Deletion ratio: 4.1%

4.1% of total churn is deletion — within normal range (flag threshold: >50%).
```

---

### 🧬 Structural drift — Layer 4

Parses every modified source file and computes exactly which named classes, functions, and constants disappeared. This is the layer that catches a file being "modified" when it's actually been gutted — line diffs alone won't tell you that `AuthManager` and `SessionStore` no longer exist.

Flags `CRITICAL` only when both conditions are met: deletion ratio exceeds the threshold **and** enough nodes were deleted. The dual gate prevents noise from small utility files.

**Supported languages:** Python · JavaScript · TypeScript · Go · Rust · Java (`.py .js .jsx .ts .tsx .go .rs .java`). Python uses stdlib AST. All others use tree-sitter. Files for grammars not installed are skipped silently.

**Python tracking includes:** named functions, classes, async functions, module-level assignments (`MAX_RETRIES = 5`), and annotated assignments (`SECRET_KEY: str = "..."`).

**Rust tracking includes:** functions, structs, enums, traits, `const` items, `static` items.

**Go tracking includes:** functions, methods, type specs, `const` specs.

```
🧬 STRUCTURAL DRIFT (Layer 4)
   Overall severity: CRITICAL
   src/core/auth.py: 8 nodes deleted (80.0%) [CRITICAL]
      - AuthManager
      - SessionStore
      - TokenValidator
      - SECRET_KEY

No significant class, function, or constant deletions detected — file content is structurally intact.
```

---

### ⏱ Temporal drift — Layer 5a

Compound score: `branch_age_days × target_commits_per_day`. Raw age alone is a weak signal — a 90-day branch on a slow repo is nothing; on a fast repo it's a serious semantic gap.

| Status | Drift Score | Meaning |
|---|---|---|
| `CURRENT` | < 250 | Branch context is valid |
| `STALE` | 250 – 999 | Moderate drift — manual diff review |
| `DANGEROUS` | ≥ 1000 | Rebase required before this goes anywhere near main |

```
⏱  TEMPORAL DRIFT (Layer 5a)
   Status: CURRENT [LOW]
   Drift Score: 14.0  (CURRENT <250 · STALE 250–1,000 · DANGEROUS ≥1,000)
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

---

### ⚠️ Commit message flags

Scans up to 50 commits between the merge base and branch tip for red-flag language: removing all tests, disabling auth, bypassing security checks, dropping a database. Surfaced as advisory — doesn't change the score, but appears prominently in the report.

---

### 🔐 Permission changes

Detects files whose mode changed — specifically files that were made executable without any content change. A script silently gaining execute permission is a supply-chain signal.

---

### 🔍 Verdict

The final call. Produced by the consequence model (Layer 3) which accumulates a weighted score across all signals.

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

### GitHub Action (recommended)

Add to `.github/workflows/payloadguard.yml`:

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

      - name: PayloadGuard
        id: payloadguard
        uses: DarkVader-PLG/payload-consequence-analyser@main
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

With [GitHub App](#github-app) secrets wired up, pass them too:

```yaml
      - name: PayloadGuard
        uses: DarkVader-PLG/payload-consequence-analyser@main
        with:
          repo-token: ${{ secrets.GITHUB_TOKEN }}
          pr-description: ${{ github.event.pull_request.body }}
          app-id: ${{ secrets.PAYLOADGUARD_APP_ID }}
          private-key: ${{ secrets.PAYLOADGUARD_PRIVATE_KEY }}
          installation-id: ${{ secrets.PAYLOADGUARD_INSTALLATION_ID }}
```

Wire a branch protection rule to require the `scan` check and the merge button is blocked on DESTRUCTIVE verdicts.

---

## GitHub App

For a named **PayloadGuard** check badge in the PR checks tab (beyond the sticky comment), register a GitHub App and wire it up with three repo secrets:

| Secret | Value |
|---|---|
| `PAYLOADGUARD_APP_ID` | Your App ID |
| `PAYLOADGUARD_PRIVATE_KEY` | Contents of the generated `.pem` private key (RSA PEM format) |
| `PAYLOADGUARD_INSTALLATION_ID` | Installation ID from `github.com/settings/installations` |

With those set, the workflow calls `post_check_run.py` to post a Check Run after each scan — green for SAFE, red for DESTRUCTIVE, with the full contextual report as the body.

Without the secrets the step is a no-op; the merge blocking still works.

---

## Configuration

Drop a `payloadguard.yml` in your repo root. Everything is optional — omit what you don't care about and the defaults hold.

```yaml
# payloadguard.yml
thresholds:
  branch_age_days: [90, 180, 365]      # score goes up at each tier
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

Threshold lists must be in ascending order — out-of-order values are auto-sorted. Tighten for anything that matters:

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

Five layers, every scan, every time.

### Scoring (Layer 3)

Points accumulate across signals. No single threshold kills you — it's the pile-up that matters.

**Branch age**

| Days old | Points |
|---|---|
| > 90 | +1 |
| > 180 | +2 |
| > 365 | +3 |

**Deletion dimensions (files deleted, deletion ratio, lines deleted)**

These three signals are highly correlated — a large destructive PR will naturally score on all three. To prevent double-counting, they are scored independently and then capped:

```
deletion_score = min(4, max(files_score, ratio_score, lines_score) + bonus)
bonus = 1 if at least 2 dimensions are non-zero, else 0
```

Individual dimension thresholds:

| Signal | Thresholds | Points |
|---|---|---|
| Files deleted | > 10 / > 20 / > 50 | 1 / 2 / 3 |
| Deletion ratio | > 50% / > 70% / > 90% | 1 / 2 / 3 |
| Lines deleted | > 5k / > 10k / > 50k | 1 / 2 / 3 |

> Deletion ratio only fires when at least 100 lines are deleted.

**Critical path weighting**

Files matching high-value path patterns (tests, CI workflows, auth, schema, migrations, entry points) carry extra weight:

| Critical files deleted | Points |
|---|---|
| > 5 | +2 |
| > 0 | +1 |

**Structural severity**

| Condition | Points |
|---|---|
| Layer 4 severity = CRITICAL | +3 |

**Verdict thresholds**

| Score | Verdict |
|---|---|
| 0 | SAFE |
| 1–2 | REVIEW |
| 3–4 | CAUTION |
| ≥ 5 | DESTRUCTIVE |

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

   61 files deleted — massive scope (flag threshold: >10 REVIEW · >20 CAUTION · >50 DESTRUCTIVE).

📝 LINE CHANGES
   Added:        214 lines
   Deleted:   11,967 lines
   Net:       -11,753 lines
   Deletion ratio: 98.2%

   98.2% deletion ratio — almost the entire changeset is deletions (threshold: >90% → DESTRUCTIVE).

🧬 STRUCTURAL DRIFT (Layer 4)
   Overall severity: CRITICAL
   Max deletion ratio: 94.0%
   src/core/auth.py: 12 nodes deleted (94.0%) [CRITICAL]
      - AuthManager
      - SessionStore
      - TokenValidator
      - PermissionGate
      - RoleRegistry

   Named structural components have been deleted at scale.

⏱  TEMPORAL DRIFT (Layer 5a)
   Status: DANGEROUS [CRITICAL]
   Drift Score: 3120.0  (CURRENT <250 · STALE 250–1,000 · DANGEROUS ≥1,000)
   Target velocity: 10.0 commits/day
   ❌ DO NOT MERGE. Extreme semantic drift detected.

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
   ⚠️  5 critical-path files deleted

✉️  RECOMMENDATION:
   ❌ DO NOT MERGE — This would catastrophically alter the codebase

======================================================================
```

Every signal was there. The age. The deletion ratio. The structural wipeout. The gap between what the description said and what the diff actually did. Nobody saw it. Now you will.

---

*PayloadGuard — because AI doesn't feel bad about what it breaks.*
